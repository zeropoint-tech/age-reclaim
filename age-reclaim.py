#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2025 ZeroPoint Technologies AB
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from collections import defaultdict
from dataclasses import dataclass, asdict
import errno
import logging
from pathlib import Path
import re
import csv
import time
from typing import Dict, List, Optional

PAGE_SIZE_BYTES = 4096

# Defined in include/linux/mmzone.h
MAX_NR_GENS = 4


# From mm/vmscan.c:isolate_folios():
# Interpret swappiness 1 as file first and MAX_SWAPPINESS as anon first.
# MAX_SWAPPINESS = 200 (defined in include/linux/swap.h)
SWAPPINESS_FILE_FIRST = 1
SWAPPINESS_ANON_FIRST = 200

GEN_ADD_MONITOR_DELAY_SEC = 3

CGGROUP_RE = re.compile(r"memcg\s+(\d+)\s+\/(.+)")
NODE_RE = re.compile(r"^ node\s+(\d+)")
GENERATION_RE = re.compile(r"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")

LRU_GEN_DEBUGFS = Path("/sys/kernel/debug/lru_gen")

STATS_CSV_FIELDNAMES = ["timestamp", "node", "gen_nr", "age", "anon", "file"]

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)s] %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


@dataclass
class LRUGeneration:
    """Representation of a generation in the lru_gen debugfs file."""

    gen_nr: int
    age: int
    anon: int
    file: int

    def memory(self) -> int:
        """The total memory of the generation in bytes."""
        return self.anon + self.file


def lru_gen_read(cgroup: str, print_debug_stats: bool):
    """Parse the raw page age data from the cgroup file."""
    node_info: Dict[int, List[LRUGeneration]] = defaultdict(list)
    in_cgroup = False
    cgroup_id = None
    node = None
    for line in LRU_GEN_DEBUGFS.read_text().splitlines():
        if match := CGGROUP_RE.match(line):
            if match.group(2) == cgroup:
                assert not in_cgroup
                in_cgroup = True
                cgroup_id = int(match.group(1))
            elif in_cgroup:
                # Finished processing the target cgroup
                break
        elif in_cgroup and (match := NODE_RE.match(line)):
            node = int(match.group(1))
        elif in_cgroup and (match := GENERATION_RE.match(line)):
            assert node is not None
            gen_nr = int(match.group(1))
            age = int(match.group(2))
            anon = int(match.group(3)) * PAGE_SIZE_BYTES
            file = int(match.group(4)) * PAGE_SIZE_BYTES
            node_info[node].append(
                LRUGeneration(gen_nr=gen_nr, age=age, anon=anon, file=file)
            )
    assert cgroup_id is not None

    if print_debug_stats:
        debug_stats(node_info)

    return cgroup_id, node_info


def lru_gen_write(cmd: str) -> bool:
    """Best-effort write to /sys/kernel/debug/lru_gen."""
    try:
        LRU_GEN_DEBUGFS.write_text(cmd)
        return True
    except OSError as e:
        err_number = e.errno
        if err_number is None:
            logger.warning(
                f"lru_gen command `{cmd.strip()}` failed due to write error: {e}"
            )
        else:
            err_symbol = errno.errorcode.get(err_number, "UNKNOWN")
            logger.warning(
                f"lru_gen command `{cmd.strip()}` failed due to write error: {err_symbol} ({err_number})"
            )
        return False


def debug_stats(node_info: Dict[int, List[LRUGeneration]]):
    total_memory = sum(
        sum(generation.memory() for generation in info) for info in node_info.values()
    )
    if total_memory == 0:
        logger.debug(f"Zero memory usage, skipping debug output.")
        return

    for node, info in node_info.items():
        for generation in info:
            logger.debug(
                f"node={node:<10} gen_nr={generation.gen_nr:<10} age_ms={generation.age:<10} "
                f"memory_mb={generation.memory()/2**20:<10.2f} "
                f"memory_pct={100*generation.memory()/total_memory:<7.2f}"
            )


def write_csv_header(csv_path: Optional[str]):
    """Write the CSV header if a path is provided."""
    if not csv_path:
        return
    with open(csv_path, "w") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=STATS_CSV_FIELDNAMES,
        )
        writer.writeheader()


def lru_gen_export_csv(
    timestamp: int,
    node_info: Dict[int, List[LRUGeneration]],
    csv_path: Optional[str],
):

    if not csv_path:
        return
    with open(csv_path, "a") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=STATS_CSV_FIELDNAMES,
        )
        for node, info in node_info.items():
            for generation in info:
                writer.writerow(
                    {"timestamp": timestamp, "node": node, **asdict(generation)}
                )


def lru_gen_add(cgroup_id: int, node_info: Dict[int, List[LRUGeneration]]):
    can_swap = 1
    force_scan = 1
    for node, info in node_info.items():
        max_gen_nr = max((gen.gen_nr for gen in info))
        logger.info(f"+ {cgroup_id=} {node=} {max_gen_nr=} {can_swap=} {force_scan=}")
        if not lru_gen_write(
            f"+ {cgroup_id} {node} {max_gen_nr} {can_swap} {force_scan}\n"
        ):
            logger.warning(f"Failed to add generation for node {node}")


class ReclaimCommand:
    """Command to reclaim memory for a specific MGLRU generation (either file, anon or both)."""

    def __init__(
        self,
        cgroup_id: int,
        node: int,
        generation: LRUGeneration,
        reclaim_anon: bool,
        reclaim_file: bool,
    ):
        self.gen_nr = generation.gen_nr
        self.cgroup_id = cgroup_id
        self.node = node
        self.swappiness = None
        if reclaim_anon and reclaim_file:
            self.nr_to_reclaim = generation.memory() // PAGE_SIZE_BYTES
        elif reclaim_anon:
            self.nr_to_reclaim = generation.anon // PAGE_SIZE_BYTES
            self.swappiness = SWAPPINESS_ANON_FIRST
        elif reclaim_file:
            self.nr_to_reclaim = generation.file // PAGE_SIZE_BYTES
            self.swappiness = SWAPPINESS_FILE_FIRST
        else:
            raise ValueError("At least one of anon or file must be set")

    def command(self) -> str:
        """Generate the command string for reclaiming memory."""
        if self.swappiness is None:
            # No need to pass nr_to_reclaim when reclaiming the whole generation
            return f"- {self.cgroup_id} {self.node} {self.gen_nr}\n"
        else:
            return f"- {self.cgroup_id} {self.node} {self.gen_nr} {self.swappiness} {self.nr_to_reclaim}\n"

    def __str__(self):
        reclaim_mb = self.nr_to_reclaim * PAGE_SIZE_BYTES / 2**20
        return f"- cgroup_id={self.cgroup_id} node={self.node} min_gen_nr={self.gen_nr} swappiness={self.swappiness} memory_mb={reclaim_mb:.2f}\n"


def do_reclaim(
    cgroup_id: int,
    reclaim_anon: bool,
    reclaim_file: bool,
    reclaim_node: int,
    reclaim_age_sec: int,
    node_info: Dict[int, List[LRUGeneration]],
):
    reclaim_info = node_info[reclaim_node]
    if len(reclaim_info) < MAX_NR_GENS:
        logger.info(
            f"Skipping reclaim for node {reclaim_node} as it has "
            f"{len(reclaim_info)}<{MAX_NR_GENS=} generations"
        )
        return

    cold_generations = sorted(
        [gen for gen in reclaim_info if gen.age > reclaim_age_sec * 1000],
        key=lambda x: x.gen_nr,
    )
    if not cold_generations:
        logger.info(
            f"Skipping reclaim for node {reclaim_node}: no generations older than {reclaim_age_sec} seconds"
        )
        return

    # Reclaim oldest generation (min gen_nr)
    reclaim_cmd = ReclaimCommand(
        cgroup_id=cgroup_id,
        node=reclaim_node,
        generation=cold_generations[0],
        reclaim_anon=reclaim_anon,
        reclaim_file=reclaim_file,
    )
    logger.info(reclaim_cmd)
    if not lru_gen_write(reclaim_cmd.command()):
        logger.error(f"Failed to reclaim memory for node {reclaim_node}")


def parse_bool(value: str) -> bool:
    """Parse a string into a boolean value."""
    if value.lower() in ("yes", "true", "1"):
        return True
    elif value.lower() in ("no", "false", "0"):
        return False
    else:
        raise ValueError(f"Invalid boolean value: {value}")


def main():
    parser = ArgumentParser(
        description="Export workingset from a cgroup into a CSV",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("cgroup", help="Path to the cgroup", type=str)
    parser.add_argument(
        "--csv",
        help="Write a CSV with the LRU statistics at each monitoring at the given path",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--print-debug-stats",
        "-d",
        action="store_true",
        help="Print out debug statistics",
    )
    parser.add_argument(
        "--reclaim",
        type=int,
        default=None,
        help="Reclaim generations older than this many seconds",
    )
    parser.add_argument(
        "--monitor",
        type=int,
        default=40,
        help="Interval for LRU_GEN generation update in seconds; autotuned when --reclaim is set",
    )
    parser.add_argument(
        "--reclaim-node",
        type=int,
        default=0,
        help="NUMA node that pages are reclaimed from",
    )
    parser.add_argument(
        "--allow-swap", action="store_true", help="Allow the cgroup to use swap"
    )
    parser.add_argument(
        "--anon",
        type=parse_bool,
        default=True,
        help="Reclaim anonymous pages",
    )
    parser.add_argument(
        "--file",
        type=parse_bool,
        default=True,
        help="Reclaim file pages",
    )
    args = parser.parse_args()

    assert args.file or args.anon, "At least one of --file or --anon must be set"

    if args.reclaim:
        logger.info(
            f"Auto-tuning monitoring and monitor intervals for reclaiming {args.reclaim} seconds"
        )
        args.monitor = args.reclaim // (MAX_NR_GENS - 1)

    cgroup_path = Path(args.cgroup)
    assert cgroup_path.exists(), f"Cgroup {cgroup_path} does not exist"
    cgroup_name = str(args.cgroup).removeprefix("/sys/fs/cgroup/").removesuffix("/")

    logger.info("Configuration:")
    logger.info(f"{'cgroup':<15} = {args.cgroup}")
    logger.info(f"{'cgroup_name':<15} = {cgroup_name}")
    logger.info(f"{'csv':<15} = {args.csv}")
    logger.info(f"{'anon':<15} = {args.anon}")
    logger.info(f"{'file':<15} = {args.file}")
    logger.info(f"{'reclaim':<15} = {args.reclaim}")
    logger.info(f"{'monitor':<15} = {args.monitor}")
    logger.info(f"{'print_debug_stats':<15} = {args.print_debug_stats}")
    logger.info(f"{'reclaim-node':<15} = {args.reclaim_node}")

    if not args.allow_swap:
        logger.info(f"Disabling swap for cgroup {cgroup_name}")
        (cgroup_path / "memory.swap.max").write_text("0\n")

    logger.info("Initializing LRU generations...")
    node_info = {}
    for _ in range(MAX_NR_GENS):
        cgroup_id, node_info = lru_gen_read(cgroup=cgroup_name, print_debug_stats=False)
        lru_gen_add(cgroup_id, node_info)

    write_csv_header(args.csv)
    while True:
        lru_gen_add(cgroup_id, node_info)
        # In very hot workloads, pages might jump to the newest generation
        # after some ms, so wait a bit before collecting the statistics
        time.sleep(GEN_ADD_MONITOR_DELAY_SEC)

        monitor_ts = int(time.time())
        cgroup_id, node_info = lru_gen_read(
            cgroup=cgroup_name, print_debug_stats=args.print_debug_stats
        )
        lru_gen_export_csv(
            timestamp=monitor_ts,
            node_info=node_info,
            csv_path=args.csv,
        )

        if args.reclaim:
            do_reclaim(
                cgroup_id=cgroup_id,
                reclaim_anon=args.anon,
                reclaim_file=args.file,
                reclaim_node=args.reclaim_node,
                reclaim_age_sec=args.reclaim,
                node_info=node_info,
            )

        time.sleep(args.monitor)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user.")

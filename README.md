# MGLRU Working Set Monitoring and Reclaim

> [!NOTE]
> This tool currently supports only one fast-tier (RAM) NUMA node. Multiple NUMA nodes in the fast tier are currently not supported.

## Requirements

The following kernel configuration options should be set:

```
CONFIG_LRU_GEN=y
CONFIG_LRU_GEN_ENABLED=y
CONFIG_MIGRATION=y
CONFIG_CGROUPS=y
CONFIG_MEMCG=y
CONFIG_NUMA_BALANCING=y
```

## Quick Start

Enable memory tiering and the MGLRU:

```sh
echo y | sudo tee /sys/kernel/mm/lru_gen/enabled
echo 1 | sudo tee /sys/kernel/mm/numa/demotion_enabled
echo 2 | sudo tee /proc/sys/kernel/numa_balancing
```

After that, you should have at least two tiers with different NUMA nodes in each:

```sh
grep -H . /sys/devices/virtual/memory_tiering/*/nodelist
```

Create a cgroup and start a benchmark inside it:

```sh
sudo mkdir -p /sys/fs/cgroup/ws
echo $$ | sudo tee /sys/fs/cgroup/ws/cgroup.procs
stress-ng --vm 1 --vm-bytes 1G -t 5m
```

Then, in another terminal, reclaim generations older than 120 seconds from that cgroup:

```sh
sudo ./age-reclaim.py /sys/fs/cgroup/ws --print-debug-stats --reclaim 120
```

In the debug statistics of the tool, you should see a percentage of the cgroup's memory moved
to the lower tier's NUMA node(s) after approximately 120 seconds.

> [!NOTE]
> By default, the tool reclaims both `anon` and `file` pages but it can be configured to reclaim
> only `anon` or only `file` pages if desired. See `--help` for more details.

## How It Works

This script leverages the Linux kernel's Multi-Gen LRU debugfs API to monitor page coldness within a cgroup and optionally reclaim cold pages based on an age threshold.

For more information on the Multi-Gen LRU, refer to:
- [Documentation/mm/multigen_lru.rst](https://docs.kernel.org/mm/multigen_lru.html)
- [Documentation/admin-guide/mm/multigen_lru.rst](https://docs.kernel.org/admin-guide/mm/multigen_lru.html)


The utility monitors `/sys/kernel/debug/lru_gen`, which displays generation data for each cgroup and NUMA node:

```
memcg  memcg_id  memcg_path
    node  node_id
         min_gen_nr  age_in_ms  nr_anon_pages  nr_file_pages
         ...
         max_gen_nr  age_in_ms  nr_anon_pages  nr_file_pages
```

The Linux kernel supports a maximum of `MAX_NR_GENS` (typically 4) generations for tracking page age, as defined in `include/linux/mmzone.h`.

These generations act like buckets, where each bucket holds pages of a similar age.

### Page Age Tracking Process

The script aims to maintain these `MAX_NR_GENS` generations to create a spectrum of page ages.

1.  **Initialization**: At startup, the script creates `MAX_NR_GENS` generations, all with age (almost) 0.

2.  **Monitoring Cycle**: The script then enters a loop that repeats at a regular monitoring interval (let's call this interval `M`):
    *   It instructs the kernel to create a new, "youngest" generation. Pages accessed recently will typically be associated with this new generation.
    *   It then reads the age and size of all existing generations.

This periodic creation of a new generation causes existing generations to "age." The newest generation is always (approximately) 0 ms old (in reality slightly older, to allow recent accesses to be captured).
The next generation becomes `M` ms old, the next `2M`, and so on.

This creates a sliding window of page ages, as illustrated below (where `max_gen_nr` is the youngest and `min_gen_nr` is the oldest):

| Time  | max_gen_nr | ... | ... | min_gen_nr |
|-------|------------|-----|-----|------------|
| t=0   | 0          | 0   | 0   | 0          |
| t=M   | 0          | M   | M   | M          |
| t=2M  | 0          | M   | 2M  | 2M         |
| t≥3M  | 0          | M   | 2M  | 3M         |

After `(MAX_NR_GENS - 1) * M` time (e.g., `3M` if `MAX_NR_GENS` is 4), the oldest generation (`min_gen_nr`) will consistently contain pages that have not been active for at least that duration.

### Cold Page Reclamation

The goal of reclamation is to identify and move pages that have been "cold" (not recently used) for a certain period. The script uses the age of the `min_gen_nr` (the oldest generation) as an indicator of the coldest pages and instructs the kernel to reclaim pages belonging to this oldest generation.

More specifically, when you use the `--reclaim R` option (e.g., `--reclaim 120` to target pages older than 120 seconds), the script automatically adjusts its internal monitoring interval `M`.
so that the age of `min_gen_nr` (which is roughly `(MAX_NR_GENS - 1) * M`) aligns with your specified reclamation threshold `R`.

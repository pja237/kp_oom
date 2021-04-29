# kp_oom

## Description

An unorthodox approach (poc) of working around the following issue:

[Singularity, cgroup memory.limits, mmaped strangeness](https://github.com/hpcng/singularity/issues/5850)

## How it works

The idea is to try and outrace the situation observed [here](https://github.com/hpcng/singularity/issues/5850) by preemptively terminating the slurm-singularity job which is about to reach the memory limit and trigger the stalling situation described in the issue above.

This is a kernel module which attaches a kprobe to `try_to_free_mem_cgroup_pages` function.

Upon triggering, in pre_handler , we check some preconditions the triggering process must meet:

1. it is a child of slurmstepd
2. it is a child of singularity

If both are true, the probe does:

1. SLURM NOTIFICATION: fires an event to its ancestors slurmstepd's eventfd to notify slurm there is an _"oom"_  about to happen in that cgroup
2. JOB TERMINATION: terminates the slurmstepd child which is an ancestor of the triggering process with SIGKILL (_"oom"_)

## Build module

```
make
```

## Insert module

* sparse output...

```
insmod kp_oom.ko
```

* with debugging enabled

```
insmod kp_oom.ko dyndbg=+pmfl
```

## Tested platform

```
CentOS Linux release 7.9.2009 (Core)
3.10.0-1127.19.1.el7.x86_64 x86_64 GNU/Linux
singularity version 3.6.4-1.el7
```

## Tests

* [mempoc](https://gist.github.com/pja237/b0e9a49be64a20ad1af905305487d41a)
* [singularity def file for image](https://github.com/pja237/kp_oom/blob/main/sing.def)

### Tests passing:

#### Must be caught with kp_oom and report oom event(s) to slurm

* `salloc --reservation=pj srun singularity run /groups/it/pja/sing/centos.img mempoc 2 16`
* `sbatch --reservation=pj --wrap='singularity run /groups/it/pja/sing/centos.img mempoc 2 16'`
* `srun --reservation=pj --pty singularity run /groups/it/pja/sing/centos.img mempoc 2 16;`

#### Must NOT be caught with kp_oom but executed with regular memcg oom handler

* `salloc --reservation=pj srun /groups/it/pja/sing/mempoc 2 16`
* `sbatch --reservation=pj --wrap='/groups/it/pja/sing/mempoc 2 16'`
* `srun --reservation=pj --pty /groups/it/pja/sing/mempoc 2 16;`

### Tests failing:




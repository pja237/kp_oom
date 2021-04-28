# kp_oom

## Description

A very brutal and violent way of working around the following issue:

[Singularity, cgroup memory.limits, mmaped strangeness](https://github.com/hpcng/singularity/issues/5850)

## How it works

...to be filled out.

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




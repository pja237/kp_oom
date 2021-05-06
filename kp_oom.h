#include <net/sock.h>
#include <net/tcp_memcontrol.h>

struct mem_cgroup_lru_info {
	struct mem_cgroup_per_node *nodeinfo[0];
};

enum mem_cgroup_events_target {
	MEM_CGROUP_TARGET_THRESH,
	MEM_CGROUP_TARGET_SOFTLIMIT,
	MEM_CGROUP_TARGET_NUMAINFO,
	MEM_CGROUP_NTARGETS,
};

enum mem_cgroup_events_index {
	MEM_CGROUP_EVENTS_PGPGIN,	/* # of pages paged in */
	MEM_CGROUP_EVENTS_PGPGOUT,	/* # of pages paged out */
	MEM_CGROUP_EVENTS_PGFAULT,	/* # of page-faults */
	MEM_CGROUP_EVENTS_PGMAJFAULT,	/* # of major page-faults */
	MEM_CGROUP_EVENTS_NSTATS,
};

enum mem_cgroup_stat_index {
	/*
 * 	 * For MEM_CONTAINER_TYPE_ALL, usage = pagecache + rss.
 * 	 	 */
	MEM_CGROUP_STAT_CACHE,		/* # of pages charged as cache */
	MEM_CGROUP_STAT_RSS,		/* # of pages charged as anon rss */
	MEM_CGROUP_STAT_RSS_HUGE,	/* # of pages charged as anon huge */
	MEM_CGROUP_STAT_FILE_MAPPED,	/* # of pages charged as file rss */
	MEM_CGROUP_STAT_SWAP,		/* # of pages, swapped out */
	MEM_CGROUP_STAT_NSTATS,
};

struct mem_cgroup_stat_cpu {
	long count[MEM_CGROUP_STAT_NSTATS];
	unsigned long events[MEM_CGROUP_EVENTS_NSTATS];
	unsigned long nr_page_events;
	unsigned long targets[MEM_CGROUP_NTARGETS];
};

struct mem_cgroup_thresholds {
	/* Primary thresholds array */
	struct mem_cgroup_threshold_ary *primary;
	/*
 * 	 * Spare threshold array.
 * 	 	 * This is needed to make mem_cgroup_unregister_event() "never fail".
 * 	 	 	 * It must be able to store at least primary->size - 1 entries.
 * 	 	 	 	 */
	struct mem_cgroup_threshold_ary *spare;
};

struct mem_cgroup {
	struct cgroup_subsys_state css;

	/* Private memcg ID. Used to ID objects that outlive the cgroup */
	unsigned short id;

	/*
	 * the counter to account for memory usage
	 */
	struct page_counter memory;

	unsigned long soft_limit;

	/* vmpressure notifications */
	struct vmpressure vmpressure;

	union {
		/*
		 * the counter to account for mem+swap usage.
		 */
		struct page_counter memsw;
		/*
		 * rcu_freeing is used only when freeing struct mem_cgroup,
		 * so put it into a union to avoid wasting more memory.
		 * It must be disjoint from the css field.  It could be
		 * in a union with the res field, but res plays a much
		 * larger part in mem_cgroup life than memsw, and might
		 * be of interest, even at time of free, when debugging.
		 * So share rcu_head with the less interesting memsw.
		 */
		struct rcu_head rcu_freeing;
		/*
		 * We also need some space for a worker in deferred freeing.
		 * By the time we call it, rcu_freeing is no longer in use.
		 */
		struct work_struct work_freeing;
	};
	/*
	 * the counter to account for kernel memory usage.
	 */
	struct page_counter kmem;
	/*
	 * Should the accounting and control be hierarchical, per subtree?
	 */
	bool use_hierarchy;
	unsigned long kmem_account_flags; /* See KMEM_ACCOUNTED_*, below */

	bool		oom_lock;
	atomic_t	under_oom;
	atomic_t	oom_wakeups;

	atomic_t	refcnt;

	int	swappiness;
	/* OOM-Killer disable */
	int		oom_kill_disable;

	/* set when res.limit == memsw.limit */
	bool		memsw_is_minimum;

	/* protect arrays of thresholds */
	struct mutex thresholds_lock;

	/* thresholds for memory usage. RCU-protected */
	struct mem_cgroup_thresholds thresholds;

	/* thresholds for mem+swap usage. RCU-protected */
	struct mem_cgroup_thresholds memsw_thresholds;

	/* For oom notifier event fd */
	struct list_head oom_notify;

	/*
	 * Should we move charges of a task when a task is moved into this
	 * mem_cgroup ? And what type of charges should we move ?
	 */
	unsigned long 	move_charge_at_immigrate;
	/*
	 * set > 0 if pages under this cgroup are moving to other cgroup.
	 */
	atomic_t	moving_account;
	/* taken only while moving_account > 0 */
	spinlock_t	move_lock;
	/*
	 * percpu counter.
	 */
	struct mem_cgroup_stat_cpu __percpu *stat;
	/*
	 * used when a cpu is offlined or other synchronizations
	 * See mem_cgroup_read_stat().
	 */
	struct mem_cgroup_stat_cpu nocpu_base;
	spinlock_t pcp_counter_lock;

	atomic_t	dead_count;
#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_INET)
	struct tcp_memcontrol tcp_mem;
#endif
#if defined(CONFIG_MEMCG_KMEM)
	/* analogous to slab_common's slab_caches list, but per-memcg;
	 * protected by memcg_slab_mutex */
	struct list_head memcg_slab_caches;
	RH_KABI_DEPRECATE(struct mutex, slab_caches_mutex)
        /* Index in the kmem_cache->memcg_params->memcg_caches array */
	int kmemcg_id;
#endif

	int last_scanned_node;
#if MAX_NUMNODES > 1
	nodemask_t	scan_nodes;
	atomic_t	numainfo_events;
	atomic_t	numainfo_updating;
#endif

	/*
	 * Per cgroup active and inactive list, similar to the
	 * per zone LRU lists.
	 *
	 * WARNING: This has to be the last element of the struct. Don't
	 * add new fields after this point.
	 */
	struct mem_cgroup_lru_info info;
};

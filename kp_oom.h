
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
};

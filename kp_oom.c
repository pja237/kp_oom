#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/eventfd.h>

#define KALLSYM "try_to_free_mem_cgroup_pages"
#define SLURM "slurmstepd"

MODULE_DESCRIPTION("kprobes kernel module");
MODULE_AUTHOR("pj");
MODULE_LICENSE("GPL");

static struct kprobe kp;

int kp_pre(struct kprobe *k, struct pt_regs *r)
{
    struct task_struct *tmp_ts;
    const struct cred *cred = current_cred();
    // --------------------------------------------------------------------------------
    // eventfd vars
    // --------------------------------------------------------------------------------
    struct file * efd_file = NULL;          //...to eventfd's file struct
    struct eventfd_ctx * efd_ctx = NULL;        //...and finally to eventfd context
    uint64_t plus_one = 1;
    // --------------------------------------------------------------------------------

    // if we're an exiting slurmstepd, don't do anything.... abort this path!
    pr_debug("KPROBE PRE-FIRE on %s from pid=%d!\n", KALLSYM, current->pid);
    if(strncmp(current->comm, SLURM, sizeof(SLURM)) == 0) {
        pr_debug(" Exiting slurmstepd, ignore.\n");
        return 0;
    }

    // if this is called from somewhere that is not a descendant of slurmstepd, also abort!
    tmp_ts=current;
    while(tmp_ts->pid != 1 && strncmp(tmp_ts->parent->comm, SLURM, sizeof(SLURM)) != 0) {
        pr_debug("WALK UP tmp_ts pid=%d comm=%s\n", tmp_ts->pid, tmp_ts->comm);
        tmp_ts=tmp_ts->parent;
    }
    pr_debug("WALK TOP pid=%d comm=%s\n", tmp_ts->pid, tmp_ts->comm);
    if(tmp_ts->pid == 1) {
        // we have walked all the way up to the top, so we didn't come from slurm => abort!
        return 0;
    }
    // here tmp_ts is pointing to the 1st descendant of slurmstepd, meaning... 
    // ...we could try to terminate that one
    // ...also tmp_ts->parent is pointing to slurmstepd which we need for eventfd below! Excellent!

    // --------------------------------------------------------------------------------
    // This eventfd snippet comes from https://stackoverflow.com/questions/13607730/writing-to-eventfd-from-kernel-module
    // --------------------------------------------------------------------------------
    pr_debug("tmp_ts->parent pid=%d comm=%s\n", tmp_ts->parent->pid, tmp_ts->parent->comm);
    // ok, we're here, lets try to send an event
    rcu_read_lock();
    // slurm efd = 17 ?always? or implement some detection logic (vomit)
    efd_file = fcheck_files(tmp_ts->parent->files, 17);
    rcu_read_unlock();
    efd_ctx = eventfd_ctx_fileget(efd_file);
    if (!efd_ctx) {
        pr_debug("eventfd_ctx_fileget() FAILED\n");
        // uh-oh.... dragons ahead!?!
        return -1;
    }
    pr_debug("Resolved pointer to the userspace program's eventfd's context: %p \n", efd_ctx);

    eventfd_signal(efd_ctx, plus_one);

    pr_debug("Incremented userspace program's eventfd's counter by 1\n");

    eventfd_ctx_put(efd_ctx);
    // --------------------------------------------------------------------------------
    // EOSTEAL
    // --------------------------------------------------------------------------------
    //
    // Now we terminate the task (current)...
    // OR... terminate 1st descendant of slurmstepd (tmp_ts) and by that terminate the job itself
    // OR BOTH!?
    // force_sig(9, current);
    // send_sig(9, current, 0);
    //
    // pr_alert("Call send_sig(SIGKILL) on pid=%d comm=%s\n", tmp_ts->pid, tmp_ts->comm);
    pr_alert("Call send_sig(SIGKILL) on pid=%d comm=%s job=%s uid=%d\n", tmp_ts->pid, tmp_ts->comm, tmp_ts->parent->comm, cred->uid.val);
    send_sig(9, tmp_ts, 0);
    pr_alert("...call finished\n");
    return 0;
}

void kp_post(struct kprobe *k, struct pt_regs *r, unsigned long flags)
{
    pr_debug("kprobe post-FIRE on %s!\n", KALLSYM);
    return;
}

int kp_fault(struct kprobe *k, struct pt_regs *r, int trapnr)
{
    pr_debug("kprobe FAULT!\n");
    return 0;
}

int dummy_init(void)
{
        unsigned long symbol_address;

        pr_alert("kp_oom init\n");
        pr_alert("kp_oom init of kprobe\n");
        kp.pre_handler=kp_pre;
        kp.post_handler=kp_post;
        kp.fault_handler=kp_fault;
        symbol_address=kallsyms_lookup_name(KALLSYM);
        pr_alert("kp_oom found symbol %s at: %lx\n", KALLSYM, symbol_address);
        kp.addr=(kprobe_opcode_t *) symbol_address;
        register_kprobe(&kp);
        return 0;
}

void dummy_exit(void)
{
        unregister_kprobe(&kp);
        pr_alert("kp_oom exit\n");
}

module_init(dummy_init);
module_exit(dummy_exit);


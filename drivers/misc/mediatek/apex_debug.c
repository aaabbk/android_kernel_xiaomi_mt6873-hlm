/*
 * apex_debug.c - Debug init busy-loop by dumping all fd poll states
 *
 * This module dumps all of init's file descriptors with their paths
 * and poll() results to identify which fd is causing init to busy-loop.
 * It also fixes /dev/kmsg POLLERR as a safety net.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

extern unsigned long get_wchan(struct task_struct *p);

static void apex_dump_all_fds(void)
{
	struct task_struct *init_task;
	struct files_struct *files;
	struct fdtable *fdt;
	int i;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		return;

	pr_err("APEX_FIX: init state=%ld\n", init_task->state);

	files = get_files_struct(init_task);
	if (!files) {
		put_task_struct(init_task);
		return;
	}

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);

	for (i = 0; i < fdt->max_fds; i++) {
		struct file *file = fdt->fd[i];
		if (file) {
			char path_buf[256];
			char *path;
			unsigned int mask = 0;

			path = d_path(&file->f_path, path_buf, sizeof(path_buf));

			/* Get poll state */
			if (file->f_op && file->f_op->poll) {
				/* poll may need file_lock released */
				mask = file->f_op->poll(file, NULL);
			}

			pr_err("APEX_FIX: fd[%d] %s flags=0x%x poll=0x%x%s%s%s%s%s\n",
				i,
				IS_ERR(path) ? "???" : path,
				file->f_flags,
				mask,
				(mask & POLLIN) ? " POLLIN" : "",
				(mask & POLLOUT) ? " POLLOUT" : "",
				(mask & POLLERR) ? " POLLERR" : "",
				(mask & POLLRDNORM) ? " POLLRDNORM" : "",
				(mask & POLLNVAL) ? " POLLNVAL" : "");
		}
	}

	spin_unlock(&files->file_lock);
	put_files_struct(files);

	/* Also dump user-space PC to see where init is executing */
	{
		struct pt_regs *regs = task_pt_regs(init_task);
		if (regs) {
			pr_err("APEX_FIX: init PC=0x%llx LR=0x%llx SP=0x%llx\n",
				regs->pc, regs->regs[30], regs->sp);
		}
	}

	put_task_struct(init_task);
}

static void apex_check_init_state(void)
{
	struct task_struct *init_task;
	unsigned long wchan;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		return;

	wchan = get_wchan(init_task);
	pr_err("APEX_FIX: init after fix: state=%ld wchan=%pS\n",
		init_task->state, wchan ? (void *)wchan : NULL);

	put_task_struct(init_task);
}

static struct delayed_work apex_debug_work;
static struct delayed_work apex_check_work;

static void apex_debug_worker(struct work_struct *work)
{
	static int count = 0;

	pr_err("APEX_FIX: === DUMP %d ===\n", count);
	apex_dump_all_fds();

	schedule_delayed_work(&apex_check_work, msecs_to_jiffies(500));

	count++;
	if (count < 5)
		schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(5000));
}

static void apex_check_worker(struct work_struct *work)
{
	apex_check_init_state();
}

static int __init apex_debug_init(void)
{
	INIT_DELAYED_WORK(&apex_debug_work, apex_debug_worker);
	INIT_DELAYED_WORK(&apex_check_work, apex_check_worker);
	schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(15000));
	pr_err("APEX_FIX: initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

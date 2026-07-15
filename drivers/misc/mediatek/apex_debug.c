/*
 * apex_debug.c - Fix apexd boot hang by clearing /dev/kmsg POLLERR
 *
 * Root cause: init opens /dev/kmsg as O_WRONLY for KernelLogger.
 * When kernel log buffer overflows, devkmsg_poll returns POLLERR
 * because user->seq < log_first_seq. Since init can't read (O_WRONLY),
 * POLLERR is never cleared, causing poll() to always return immediately
 * → init busy-loops → apexd's property set never gets processed.
 *
 * Fix: directly advance user->seq past log_next_seq to clear POLLERR.
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
extern u64 log_next_seq;  /* from kernel/printk/printk.c */

/* devkmsg_user struct layout (from v4.14 kernel/printk/printk.c):
 *   u64 seq;          offset 0
 *   u32 idx;          offset 8
 *   struct mutex lock; offset 12 (or 16 with alignment)
 *   char buf[];       after mutex
 * We only need to modify seq (first 8 bytes).
 */

static void apex_fix_kmsg_pollerr(void)
{
	struct task_struct *init_task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *kmsg_file = NULL;
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
			char path_buf[128];
			char *path;

			path = d_path(&file->f_path, path_buf, sizeof(path_buf));
			if (!IS_ERR(path) && strcmp(path, "/dev/kmsg") == 0) {
				kmsg_file = get_file(file);
				break;
			}
		}
	}
	spin_unlock(&files->file_lock);
	put_files_struct(files);
	put_task_struct(init_task);

	if (!kmsg_file) {
		pr_err("APEX_FIX: /dev/kmsg not found\n");
		return;
	}

	/* Check poll before fix */
	if (kmsg_file->f_op && kmsg_file->f_op->poll) {
		unsigned int mask = kmsg_file->f_op->poll(kmsg_file, NULL);
		pr_err("APEX_FIX: poll before: 0x%x%s%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLPRI) ? " POLLPRI" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLRDNORM) ? " POLLRDNORM" : "");
	}

	/* Directly modify devkmsg_user->seq to clear POLLERR.
	 * Setting seq to log_next_seq makes user->seq == log_next_seq,
	 * so the condition (user->seq < log_next_seq) becomes false,
	 * and devkmsg_poll returns 0 (no events). */
	if (kmsg_file->private_data) {
		u64 *user_seq = (u64 *)kmsg_file->private_data;
		u64 old_seq = *user_seq;

		/* Advance seq to current log_next_seq */
		*user_seq = log_next_seq;

		pr_err("APEX_FIX: advanced user->seq from %llu to %llu (log_next_seq)\n",
			old_seq, log_next_seq);
	}

	/* Check poll after fix */
	if (kmsg_file->f_op && kmsg_file->f_op->poll) {
		unsigned int mask = kmsg_file->f_op->poll(kmsg_file, NULL);
		pr_err("APEX_FIX: poll after: 0x%x%s%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLPRI) ? " POLLPRI" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLRDNORM) ? " POLLRDNORM" : "");
	}

	fput(kmsg_file);
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

	pr_err("APEX_FIX: === FIX %d ===\n", count);
	apex_fix_kmsg_pollerr();

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

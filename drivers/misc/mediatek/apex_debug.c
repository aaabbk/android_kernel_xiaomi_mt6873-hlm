/*
 * apex_debug.c - Safety net for apexd boot hang
 *
 * Primary fix: devkmsg_poll() in printk.c now returns POLLOUT only
 * for O_WRONLY opens, preventing init from busy-looping on POLLIN.
 *
 * This module: sets init's /dev/kmsg user->seq to U64_MAX as a
 * safety net to clear any lingering POLLIN/POLLERR state.
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

/* devkmsg_user struct: first field is u64 seq (from printk.c) */

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
		pr_err("APEX_FIX: poll before: 0x%x%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLRDNORM) ? " POLLRDNORM" : "");
	}

	/* Set user->seq to U64_MAX to clear both POLLIN and POLLERR.
	 * With U64_MAX, user->seq > log_next_seq so devkmsg_poll returns
	 * no read events. This is a safety net; the primary fix is in
	 * devkmsg_poll() which skips read events for O_WRONLY opens. */
	if (kmsg_file->private_data) {
		u64 *user_seq = (u64 *)kmsg_file->private_data;
		u64 old_seq = *user_seq;

		*user_seq = U64_MAX;

		pr_err("APEX_FIX: set user->seq from %llu to U64_MAX\n",
			old_seq);
	}

	/* Check poll after fix */
	if (kmsg_file->f_op && kmsg_file->f_op->poll) {
		unsigned int mask = kmsg_file->f_op->poll(kmsg_file, NULL);
		pr_err("APEX_FIX: poll after: 0x%x%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
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

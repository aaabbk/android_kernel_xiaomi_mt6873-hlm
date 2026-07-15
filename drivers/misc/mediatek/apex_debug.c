/*
 * apex_debug.c - Fix apexd boot hang by clearing /dev/kmsg POLLERR
 *
 * Root cause: init opens /dev/kmsg for KernelLogger. When kernel log
 * buffer overflows, devkmsg_poll returns POLLERR because user->seq <
 * log_first_seq. Since init can't clear it, poll() always returns
 * immediately → init busy-loops → apexd hangs on futex_wait.
 *
 * Fix: open our own /dev/kmsg, read to get current seq, then copy
 * that seq to init's devkmsg_user to clear POLLERR.
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

/* Get current log_next_seq by opening our own /dev/kmsg and reading.
 * After a successful read, the fd's user->seq == log_next_seq. */
static u64 apex_get_current_seq(void)
{
	struct file *file;
	mm_segment_t old_fs;
	char *buf;
	ssize_t ret;
	loff_t pos = 0;
	u64 seq = 0;

	buf = kmalloc(8192, GFP_KERNEL);
	if (!buf)
		return 0;

	file = filp_open("/dev/kmsg", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(file)) {
		pr_err("APEX_FIX: can't open /dev/kmsg: %ld\n", PTR_ERR(file));
		kfree(buf);
		return 0;
	}

	/* Read one message to advance seq to current position */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_read(file, (void __user *)buf, 8191, &pos);
	set_fs(old_fs);
	kfree(buf);

	if (ret >= 0 && file->private_data) {
		/* After read, user->seq has been advanced to log_next_seq */
		seq = *(u64 *)file->private_data;
		pr_err("APEX_FIX: got seq=%llu (read ret=%zd)\n", seq, ret);
	} else if (ret == -EPIPE && file->private_data) {
		/* EPIPE means messages were lost, but seq was still advanced */
		seq = *(u64 *)file->private_data;
		pr_err("APEX_FIX: got seq=%llu after EPIPE\n", seq);
	} else {
		pr_err("APEX_FIX: read failed ret=%zd\n", ret);
	}

	filp_close(file, NULL);
	return seq;
}

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

	/* Get current log seq */
	{
		u64 current_seq = apex_get_current_seq();
		if (current_seq > 0 && kmsg_file->private_data) {
			u64 *user_seq = (u64 *)kmsg_file->private_data;
			u64 old_seq = *user_seq;

			*user_seq = current_seq;

			pr_err("APEX_FIX: advanced user->seq from %llu to %llu\n",
				old_seq, current_seq);
		} else if (kmsg_file->private_data) {
			/* Fallback: set to very large value to ensure
			 * user->seq >= log_next_seq */
			u64 *user_seq = (u64 *)kmsg_file->private_data;
			u64 old_seq = *user_seq;

			*user_seq = U64_MAX;

			pr_err("APEX_FIX: set user->seq from %llu to U64_MAX (fallback)\n",
				old_seq);
		}
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

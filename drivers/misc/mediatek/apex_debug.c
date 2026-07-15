/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Reads from init's /dev/kmsg fd to clear persistent POLLERR.
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

/* Read from init's /dev/kmsg fd to clear POLLERR. */
static void apex_clear_kmsg_pollerr(void)
{
	struct task_struct *init_task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *kmsg_file = NULL;
	mm_segment_t old_fs;
	char *buf;
	ssize_t ret;
	int i;
	unsigned int orig_flags;

	buf = kmalloc(8192, GFP_KERNEL);
	if (!buf) {
		pr_err("APEX_FIX: kmalloc failed\n");
		return;
	}

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		goto out_free;

	pr_err("APEX_FIX: init state=%ld\n", init_task->state);

	files = get_files_struct(init_task);
	if (!files) {
		put_task_struct(init_task);
		goto out_free;
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
		goto out_free;
	}

	/* Check poll before read */
	if (kmsg_file->f_op && kmsg_file->f_op->poll) {
		unsigned int mask = kmsg_file->f_op->poll(kmsg_file, NULL);
		pr_err("APEX_FIX: poll before: 0x%x%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLHUP) ? " POLLHUP" : "");
	}

	/* Temporarily set O_NONBLOCK to avoid blocking in devkmsg_read */
	orig_flags = kmsg_file->f_flags;
	kmsg_file->f_flags |= O_NONBLOCK;

	/* Read from /dev/kmsg using kernel buffer */
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	for (i = 0; i < 200; i++) {
		loff_t pos = 0;
		ret = vfs_read(kmsg_file, (void __user *)buf,
			       sizeof(buf) - 1, &pos);
		if (ret == -EPIPE) {
			if (i == 0)
				pr_err("APEX_FIX: read -EPIPE (seq advanced)\n");
			continue;
		}
		if (ret == -EAGAIN) {
			if (i == 0)
				pr_err("APEX_FIX: read -EAGAIN (empty)\n");
			break;
		}
		if (ret < 0) {
			pr_err("APEX_FIX: read error %zd\n", ret);
			break;
		}
		if (ret == 0)
			break;
	}

	set_fs(old_fs);
	kmsg_file->f_flags = orig_flags;

	pr_err("APEX_FIX: drained %d messages\n", i);

	/* Check poll after read */
	if (kmsg_file->f_op && kmsg_file->f_op->poll) {
		unsigned int mask = kmsg_file->f_op->poll(kmsg_file, NULL);
		pr_err("APEX_FIX: poll after: 0x%x%s%s%s\n",
			mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLHUP) ? " POLLHUP" : "");
	}

	fput(kmsg_file);

out_free:
	kfree(buf);
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
	apex_clear_kmsg_pollerr();

	/* Schedule state check 500ms later */
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

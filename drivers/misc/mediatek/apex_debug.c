/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Prints block device status, apexd process state, and stack trace.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/kobject.h>
#include <linux/stacktrace.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>

extern struct class block_class;
extern unsigned long get_wchan(struct task_struct *p);

static void apex_debug_dump_state(void)
{
	struct class_dev_iter iter;
	struct device *dev;
	struct gendisk *disk;
	int loop_count = 0, dm_count = 0;
	struct task_struct *t;

	pr_err("APEX_DBG: === BLOCK DEVICE DUMP ===\n");

	class_dev_iter_init(&iter, &block_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		disk = dev_to_disk(dev);
		if (!disk)
			continue;

		if (disk->disk_name[0] != '\0' &&
		    strncmp(disk->disk_name, "loop", 4) == 0) {
			pr_err("APEX_DBG: %s major=%d\n",
				disk->disk_name, disk->major);
			loop_count++;
		}
		if (disk->disk_name[0] != '\0' &&
		    strncmp(disk->disk_name, "dm-", 3) == 0) {
			pr_err("APEX_DBG: %s major=%d\n",
				disk->disk_name, disk->major);
			dm_count++;
		}
	}
	class_dev_iter_exit(&iter);

	pr_err("APEX_DBG: found %d loop, %d dm devices\n",
		loop_count, dm_count);

	/* Check apexd and init process state and stack */
	rcu_read_lock();
	for_each_process(t) {
		if (strncmp(t->comm, "apexd", 5) == 0 ||
		    strncmp(t->comm, "init", 4) == 0 ||
		    strncmp(t->comm, "servicemanager", 14) == 0 ||
		    strncmp(t->comm, "vold", 4) == 0 ||
		    strncmp(t->comm, "ueventd", 7) == 0) {
			struct stack_trace trace;
			unsigned long entries[32];
			int i;
			struct files_struct *files;
			struct fdtable *fdt;
			struct file *file;
			unsigned long wchan;

			pr_err("APEX_DBG: %s pid=%d state=%ld on_cpu=%d\n",
				t->comm, t->pid, t->state, task_curr(t));

			/* Dump wchan */
			wchan = get_wchan(t);
			if (wchan) {
				pr_err("APEX_DBG: %s wchan=%pS\n",
					t->comm, (void *)wchan);
			} else {
				pr_err("APEX_DBG: %s wchan=(running/none)\n",
					t->comm);
			}

			/* Dump stack trace */
			trace.nr_entries = 0;
			trace.entries = entries;
			trace.max_entries = 32;
			trace.skip = 0;
			save_stack_trace_tsk(t, &trace);

			pr_err("APEX_DBG: %s stack (%d frames):\n",
				t->comm, trace.nr_entries);
			for (i = 0; i < trace.nr_entries; i++) {
				pr_err("APEX_DBG:  [%d] %pS\n",
					i, (void *)entries[i]);
			}

			/* Dump open file descriptors */
			files = get_files_struct(t);
			if (files) {
				int fd_count = 0;
				spin_lock(&files->file_lock);
				fdt = files_fdtable(files);
				for (i = 0; i < fdt->max_fds && fd_count < 20; i++) {
					file = fdt->fd[i];
					if (file) {
						char buf[128];
						char *path;

						path = d_path(&file->f_path, buf, sizeof(buf));
						if (!IS_ERR(path)) {
							pr_err("APEX_DBG: %s fd[%d]=%s\n",
								t->comm, i, path);
						} else {
							pr_err("APEX_DBG: %s fd[%d]=(error)\n",
								t->comm, i);
						}
						fd_count++;
					}
				}
				spin_unlock(&files->file_lock);
				put_files_struct(files);
			}
		}
	}
	rcu_read_unlock();
	pr_err("APEX_DBG: === END DUMP ===\n");
}

static struct delayed_work apex_debug_work;

static void apex_debug_worker(struct work_struct *work)
{
	static int count = 0;

	apex_debug_dump_state();

	count++;
	if (count < 30) {
		schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(3000));
	}
}

static int apex_debug_panic(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
	pr_err("APEX_DBG: === PANIC DUMP ===\n");
	apex_debug_dump_state();
	return NOTIFY_DONE;
}

static struct notifier_block apex_debug_panic_nb = {
	.notifier_call = apex_debug_panic,
	.priority = 1,
};

static int __init apex_debug_init(void)
{
	INIT_DELAYED_WORK(&apex_debug_work, apex_debug_worker);
	schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(12000));
	atomic_notifier_chain_register(&panic_notifier_list,
				       &apex_debug_panic_nb);
	pr_err("APEX_DBG: debug tracing initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

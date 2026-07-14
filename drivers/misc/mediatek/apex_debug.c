/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Prints block device (loop/DM) status periodically and on panic.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/kobject.h>

extern struct class block_class;

static void apex_debug_dump_state(void)
{
	struct class_dev_iter iter;
	struct device *dev;
	struct gendisk *disk;
	int loop_count = 0, dm_count = 0;

	pr_err("APEX_DBG: === BLOCK DEVICE DUMP ===\n");

	class_dev_iter_init(&iter, &block_class, NULL, &disk_type);
	while ((dev = class_dev_iter_next(&iter))) {
		disk = dev_to_disk(dev);
		if (!disk || !disk->disk_name)
			continue;

		if (strncmp(disk->disk_name, "loop", 4) == 0) {
			pr_err("APEX_DBG: %s major=%d first_minor=%d\n",
				disk->disk_name, disk->major,
				disk->first_minor);
			loop_count++;
		}
		if (strncmp(disk->disk_name, "dm-", 3) == 0) {
			pr_err("APEX_DBG: %s major=%d first_minor=%d\n",
				disk->disk_name, disk->major,
				disk->first_minor);
			dm_count++;
		}
	}
	class_dev_iter_exit(&iter);

	pr_err("APEX_DBG: found %d loop devices, %d dm devices\n",
		loop_count, dm_count);

	/* Check if apexd is still running */
	{
		struct task_struct *t;
		rcu_read_lock();
		for_each_process(t) {
			if (strncmp(t->comm, "apexd", 5) == 0) {
				pr_err("APEX_DBG: apexd pid=%d state=%ld\n",
					t->pid, t->state);
			}
		}
		rcu_read_unlock();
	}
	pr_err("APEX_DBG: === END DUMP ===\n");
}

static struct delayed_work apex_debug_work;

static void apex_debug_worker(struct work_struct *work)
{
	static int count = 0;

	apex_debug_dump_state();

	count++;
	if (count < 30) {  /* Run for ~90 seconds */
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

	/* Start at 12 seconds after boot */
	schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(12000));

	atomic_notifier_chain_register(&panic_notifier_list,
				       &apex_debug_panic_nb);

	pr_err("APEX_DBG: debug tracing initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

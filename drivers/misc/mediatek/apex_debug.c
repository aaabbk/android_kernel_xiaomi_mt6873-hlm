/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Checks which of init's open fds always has POLLIN ready.
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
#include <linux/stacktrace.h>
#include <asm/ptrace.h>

extern unsigned long get_wchan(struct task_struct *p);

#define MAX_FDS 20

struct fd_info {
	int fd;
	struct file *file;
	char path[128];
};

/* Check each fd's poll status for init (pid=1) */
static void apex_check_init_fds(void)
{
	struct task_struct *init_task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct fd_info fds[MAX_FDS];
	int nfds = 0;
	int i;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task) {
		pr_err("APEX_FD: init not found\n");
		return;
	}

	pr_err("APEX_FD: init pid=%d state=%ld\n",
		init_task->pid, init_task->state);

	files = get_files_struct(init_task);
	if (!files) {
		pr_err("APEX_FD: no files_struct\n");
		put_task_struct(init_task);
		return;
	}

	/* Phase 1: collect file references and paths under spinlock */
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);

	for (i = 0; i < fdt->max_fds && nfds < MAX_FDS; i++) {
		struct file *file = fdt->fd[i];
		if (file) {
			char buf[128];
			char *path;

			fds[nfds].fd = i;
			fds[nfds].file = get_file(file); /* inc refcount */

			path = d_path(&file->f_path, buf, sizeof(buf));
			if (!IS_ERR(path))
				snprintf(fds[nfds].path, sizeof(fds[nfds].path),
					"%s", path);
			else
				snprintf(fds[nfds].path, sizeof(fds[nfds].path),
					"(unknown)");

			nfds++;
		}
	}

	spin_unlock(&files->file_lock);
	put_files_struct(files);
	put_task_struct(init_task);

	/* Phase 2: call poll for each file (no spinlock held) */
	for (i = 0; i < nfds; i++) {
		unsigned int mask = 0;

		if (fds[i].file->f_op && fds[i].file->f_op->poll)
			mask = fds[i].file->f_op->poll(fds[i].file, NULL);

		pr_err("APEX_FD: fd[%d]=%s poll=0x%x%s%s%s%s%s\n",
			fds[i].fd, fds[i].path, mask,
			(mask & POLLIN) ? " POLLIN" : "",
			(mask & POLLOUT) ? " POLLOUT" : "",
			(mask & POLLERR) ? " POLLERR" : "",
			(mask & POLLHUP) ? " POLLHUP" : "",
			(mask & POLLNVAL) ? " POLLNVAL" : "");

		fput(fds[i].file); /* safe: no spinlock held */
	}
}

/* Also check apexd state */
static void apex_check_apexd(void)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_process(t) {
		if (strncmp(t->comm, "apexd", 5) == 0) {
			unsigned long wchan;
			wchan = get_wchan(t);
			pr_err("APEX_FD: apexd pid=%d state=%ld wchan=%pS\n",
				t->pid, t->state,
				wchan ? (void *)wchan : NULL);
		}
	}
	rcu_read_unlock();
}

static struct delayed_work apex_debug_work;

static void apex_debug_worker(struct work_struct *work)
{
	static int count = 0;

	pr_err("APEX_FD: === CHECK %d ===\n", count);
	apex_check_init_fds();
	apex_check_apexd();
	pr_err("APEX_FD: === END ===\n");

	count++;
	if (count < 10)
		schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(5000));
}

static int apex_debug_panic(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
	pr_err("APEX_FD: === PANIC ===\n");
	apex_check_init_fds();
	return NOTIFY_DONE;
}

static struct notifier_block apex_debug_panic_nb = {
	.notifier_call = apex_debug_panic,
	.priority = 1,
};

static int __init apex_debug_init(void)
{
	INIT_DELAYED_WORK(&apex_debug_work, apex_debug_worker);
	schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(15000));
	atomic_notifier_chain_register(&panic_notifier_list,
				       &apex_debug_panic_nb);
	pr_err("APEX_FD: initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

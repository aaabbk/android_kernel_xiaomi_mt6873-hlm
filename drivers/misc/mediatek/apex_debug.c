/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Traces init's poll() by reading pollfd from user-space stack via IPI.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/stacktrace.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <asm/ptrace.h>

extern struct class block_class;
extern unsigned long get_wchan(struct task_struct *p);

/* IPI handler: dump init's user-space PC and read pollfd from stack.
 * Runs in interrupt context on init's CPU, with current=init. */
static void ipi_dump_current_stack(void *info)
{
	struct task_struct *t = current;
	struct pt_regs *regs;

	if (t->pid != 1)
		return;

	regs = task_pt_regs(t);
	if (!regs)
		return;

	if (user_mode(regs)) {
		unsigned long sp = regs->sp;
		struct pollfd pfd;
		int i;
		/* pollfd offsets from disassembly: sp+0x1d8 is primary.
		 * Also check nearby offsets in case stack layout varies. */
		int offsets[] = {0x1d8, 0x1e0, 0x1d0, 0x1c8, 0x1e8};

		pr_err("APEX_CPU: init PC=0x%llx LR=0x%llx SP=0x%llx\n",
			regs->pc, regs->regs[30], sp);

		/* Read pollfd from user-space stack.
		 * Use __copy_from_user_inatomic since we're in IPI context. */
		for (i = 0; i < 5; i++) {
			unsigned long addr = sp + offsets[i];

			if (!__copy_from_user_inatomic(&pfd,
					(void __user *)addr,
					sizeof(pfd))) {
				if (pfd.fd >= 0 && pfd.fd < 64) {
					pr_err("APEX_CPU: pollfd sp+0x%x: fd=%d events=0x%x revents=0x%x\n",
						offsets[i], pfd.fd,
						pfd.events, pfd.revents);
				}
			}
		}
	} else {
		pr_err("APEX_CPU: init KERNEL PC=0x%llx\n", regs->pc);
	}
}

static void apex_debug_dump_fds(struct task_struct *t)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *file;
	int i;
	int fd_count = 0;

	files = get_files_struct(t);
	if (!files)
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds && fd_count < 15; i++) {
		file = fdt->fd[i];
		if (file) {
			char buf[128];
			char *path;

			path = d_path(&file->f_path, buf, sizeof(buf));
			if (!IS_ERR(path)) {
				pr_err("APEX_DBG: %s fd[%d]=%s\n",
					t->comm, i, path);
			}
			fd_count++;
		}
	}
	spin_unlock(&files->file_lock);
	put_files_struct(files);
}

static void apex_debug_dump_state(void)
{
	struct task_struct *t;

	pr_err("APEX_DBG: === DUMP START ===\n");

	rcu_read_lock();
	for_each_process(t) {
		if (strncmp(t->comm, "apexd", 5) == 0 ||
		    strncmp(t->comm, "init", 4) == 0 ||
		    strncmp(t->comm, "servicemanager", 14) == 0 ||
		    strncmp(t->comm, "vold", 4) == 0 ||
		    strncmp(t->comm, "ueventd", 7) == 0) {
			unsigned long wchan;

			pr_err("APEX_DBG: %s pid=%d state=%ld cpu=%d\n",
				t->comm, t->pid, t->state, task_cpu(t));

			wchan = get_wchan(t);
			if (wchan)
				pr_err("APEX_DBG: %s wchan=%pS\n",
					t->comm, (void *)wchan);
			else
				pr_err("APEX_DBG: %s wchan=(running)\n",
					t->comm);

			if (t->state == 0 && t->pid == 1) {
				int target_cpu = task_cpu(t);
				pr_err("APEX_DBG: IPI->cpu%d for init\n",
					target_cpu);
				smp_call_function_single(target_cpu,
					ipi_dump_current_stack, NULL, 1);
			} else if (t->state != 0) {
				struct stack_trace trace;
				unsigned long entries[32];
				int i;

				trace.nr_entries = 0;
				trace.entries = entries;
				trace.max_entries = 32;
				trace.skip = 0;
				save_stack_trace_tsk(t, &trace);

				pr_err("APEX_DBG: %s stack (%d):\n",
					t->comm, trace.nr_entries);
				for (i = 0; i < trace.nr_entries; i++)
					pr_err("APEX_DBG:  [%d] %pS\n",
						i, (void *)entries[i]);
			}

			if (strncmp(t->comm, "apexd", 5) == 0 || t->pid == 1)
				apex_debug_dump_fds(t);
		}
	}
	rcu_read_unlock();
	pr_err("APEX_DBG: === DUMP END ===\n");
}

static struct delayed_work apex_debug_work;

static void apex_debug_worker(struct work_struct *work)
{
	static int count = 0;

	apex_debug_dump_state();

	count++;
	if (count < 30)
		schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(3000));
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

/* Init tracer: every 500ms, send IPI to get init's user-space PC */
static struct delayed_work init_trace_work;

static void init_trace_worker(struct work_struct *work)
{
	struct task_struct *init_task;
	static int trace_count = 0;
	unsigned long wchan;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		goto resched;

	wchan = get_wchan(init_task);
	if (!wchan) {
		int cpu = task_cpu(init_task);
		pr_err("INIT_TRACE: [%d] init RUNNING cpu=%d\n",
			trace_count, cpu);
		smp_call_function_single(cpu, ipi_dump_current_stack, NULL, 1);
	} else {
		pr_err("INIT_TRACE: [%d] init sleeping wchan=%pS\n",
			trace_count, (void *)wchan);
	}

	put_task_struct(init_task);

resched:
	trace_count++;
	if (trace_count < 60)
		schedule_delayed_work(&init_trace_work, msecs_to_jiffies(500));
}

static int __init apex_debug_init(void)
{
	INIT_DELAYED_WORK(&apex_debug_work, apex_debug_worker);
	schedule_delayed_work(&apex_debug_work, msecs_to_jiffies(12000));

	INIT_DELAYED_WORK(&init_trace_work, init_trace_worker);
	schedule_delayed_work(&init_trace_work, msecs_to_jiffies(10000));

	atomic_notifier_chain_register(&panic_notifier_list,
				       &apex_debug_panic_nb);
	pr_err("APEX_DBG: initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

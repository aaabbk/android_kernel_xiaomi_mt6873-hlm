/*
 * apex_debug.c - Debug tracing for apexd boot issues
 *
 * Dumps raw stack bytes around pollfd to find exact poll arguments.
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

/* IPI handler: dump init's user-space PC and raw stack around pollfd */
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
		/* Dump 32 raw bytes at sp+0x1d0 to sp+0x1f0
		 * pollfd should be at sp+0x1d8 (from disassembly):
		 *   sp+0x1d8: fd (4 bytes)
		 *   sp+0x1dc: events (2 bytes)
		 *   sp+0x1de: revents (2 bytes)
		 */
		unsigned char raw[32];
		unsigned long base = sp + 0x1d0;
		int i;

		pr_err("APEX_CPU: init PC=0x%llx SP=0x%llx\n",
			regs->pc, sp);

		if (!__copy_from_user_inatomic(raw,
				(void __user *)base, sizeof(raw))) {
			/* Print as hex dump */
			pr_err("APEX_CPU: raw bytes at sp+0x1d0:\n");
			for (i = 0; i < 32; i += 8) {
				pr_err("APEX_CPU:  sp+0x%03x: %02x %02x %02x %02x %02x %02x %02x %02x\n",
					0x1d0 + i,
					raw[i], raw[i+1], raw[i+2], raw[i+3],
					raw[i+4], raw[i+5], raw[i+6], raw[i+7]);
			}

			/* Interpret pollfd at sp+0x1d8 */
			{
				int fd = *(int *)(raw + 8);      /* sp+0x1d8 */
				short events = *(short *)(raw + 12); /* sp+0x1dc */
				short revents = *(short *)(raw + 14); /* sp+0x1de */

				pr_err("APEX_CPU: pollfd@sp+0x1d8: fd=%d events=0x%x revents=0x%x\n",
					fd, (unsigned)events, (unsigned)revents);
			}

			/* Also interpret as pollfd at sp+0x1e0 */
			{
				int fd = *(int *)(raw + 16);     /* sp+0x1e0 */
				short events = *(short *)(raw + 20); /* sp+0x1e4 */
				short revents = *(short *)(raw + 22); /* sp+0x1e6 */

				pr_err("APEX_CPU: pollfd@sp+0x1e0: fd=%d events=0x%x revents=0x%x\n",
					fd, (unsigned)events, (unsigned)revents);
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
	if (count < 20)
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
	if (trace_count < 40)
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

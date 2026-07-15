/*
 * apex_debug.c - Debug init busy-loop by capturing real-time user-space PC
 *
 * Uses IPI (Inter-Processor Interrupt) to capture init's actual current
 * PC, LR, SP while it's running in user space (not in a syscall).
 * task_pt_regs() only gives stale PC from last syscall entry.
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
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <asm/ptrace.h>

extern unsigned long get_wchan(struct task_struct *p);

/* IPI capture state */
static struct {
	struct task_struct *target;
	u64 pc;
	u64 lr;
	u64 sp;
	u64 pstate;
	int cpu;
	int done;
} ipi_capture;

static void ipi_capture_fn(void *info)
{
	struct task_struct *tsk = ipi_capture.target;
	struct pt_regs *regs;

	if (!tsk || tsk != current)
		return;

	/* current is the task running on this CPU.
	 * If it's init, we can read its user-space registers.
	 * task_pt_regs() gives the exception frame which contains
	 * the user-space PC/LR/SP from the last exception entry.
	 * But since we're in an IPI (which is an exception),
	 * task_pt_regs() now contains the CURRENT user-space state! */
	regs = task_pt_regs(tsk);
	if (regs) {
		ipi_capture.pc = regs->pc;
		ipi_capture.lr = regs->regs[30];
		ipi_capture.sp = regs->sp;
		ipi_capture.pstate = regs->pstate;
		ipi_capture.cpu = smp_processor_id();
		ipi_capture.done = 1;
	}
}

static void apex_capture_init_pc(void)
{
	struct task_struct *init_task;
	int cpu;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		return;

	pr_err("APEX_FIX: init state=%ld cpu=%d\n",
		init_task->state, task_cpu(init_task));

	/* If init is running on a CPU, send IPI to capture its PC */
	if (init_task->state == 0) {  /* TASK_RUNNING */
		ipi_capture.target = init_task;
		ipi_capture.done = 0;
		cpu = task_cpu(init_task);

		smp_call_function_single(cpu, ipi_capture_fn, NULL, 1);

		if (ipi_capture.done) {
			pr_err("APEX_FIX: REAL PC=0x%llx LR=0x%llx SP=0x%llx pstate=0x%llx cpu=%d\n",
				ipi_capture.pc, ipi_capture.lr,
				ipi_capture.sp, ipi_capture.pstate,
				ipi_capture.cpu);
		} else {
			/* init might have migrated, try all online CPUs */
			for_each_online_cpu(cpu) {
				if (cpu == smp_processor_id())
					continue;
				ipi_capture.done = 0;
				smp_call_function_single(cpu, ipi_capture_fn, NULL, 1);
				if (ipi_capture.done)
					break;
			}
			if (ipi_capture.done) {
				pr_err("APEX_FIX: REAL PC=0x%llx LR=0x%llx SP=0x%llx pstate=0x%llx cpu=%d\n",
					ipi_capture.pc, ipi_capture.lr,
					ipi_capture.sp, ipi_capture.pstate,
					ipi_capture.cpu);
			} else {
				pr_err("APEX_FIX: could not capture PC (init not running?)\n");
			}
		}
	} else {
		struct pt_regs *regs = task_pt_regs(init_task);
		if (regs) {
			pr_err("APEX_FIX: STALE PC=0x%llx LR=0x%llx SP=0x%llx (state=%ld, not running)\n",
				regs->pc, regs->regs[30], regs->sp,
				init_task->state);
		}
	}

	put_task_struct(init_task);
}

static void apex_dump_fds(void)
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
			if (file->f_op && file->f_op->poll)
				mask = file->f_op->poll(file, NULL);

			pr_err("APEX_FIX: fd[%d] %s flags=0x%x poll=0x%x%s%s%s%s%s\n",
				i, IS_ERR(path) ? "???" : path,
				file->f_flags, mask,
				(mask & POLLIN) ? " IN" : "",
				(mask & POLLOUT) ? " OUT" : "",
				(mask & POLLERR) ? " ERR" : "",
				(mask & POLLRDNORM) ? " RDNORM" : "",
				(mask & POLLNVAL) ? " NVAL" : "");
		}
	}

	spin_unlock(&files->file_lock);
	put_files_struct(files);
	put_task_struct(init_task);
}

static struct delayed_work apex_work;

static void apex_worker(struct work_struct *work)
{
	static int count = 0;

	pr_err("APEX_FIX: === CAPTURE %d ===\n", count);
	apex_capture_init_pc();

	if (count == 0)
		apex_dump_fds();

	count++;
	if (count < 8)
		schedule_delayed_work(&apex_work, msecs_to_jiffies(3000));
}

static int __init apex_debug_init(void)
{
	INIT_DELAYED_WORK(&apex_work, apex_worker);
	schedule_delayed_work(&apex_work, msecs_to_jiffies(15000));
	pr_err("APEX_FIX: initialized\n");
	return 0;
}
late_initcall(apex_debug_init);

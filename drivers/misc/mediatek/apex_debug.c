/*
 * apex_debug.c - Debug init busy-loop by capturing real-time user-space PC
 * and dumping registers. Uses IPI to capture the actual current PC.
 *
 * Key findings:
 * - init is stuck in a string comparison loop (xmlStrEqual or similar)
 * - x21 has MTE tag (0xb400...) which copy_from_user can't handle
 * - PC alternates between init binary and a shared library
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

static struct {
	struct task_struct *target;
	u64 regs[31];
	u64 pc;
	u64 sp;
	u64 pstate;
	int done;
} ipi_capture;

static void ipi_capture_fn(void *info)
{
	struct task_struct *tsk = ipi_capture.target;
	struct pt_regs *regs;
	int i;

	if (!tsk || tsk != current)
		return;

	regs = task_pt_regs(tsk);
	if (regs) {
		ipi_capture.pc = regs->pc;
		ipi_capture.sp = regs->sp;
		ipi_capture.pstate = regs->pstate;
		for (i = 0; i < 31; i++)
			ipi_capture.regs[i] = regs->regs[i];
		ipi_capture.done = 1;
	}
}

static u64 untag_addr(u64 addr)
{
	/* Remove MTE tag (top byte) for copy_from_user */
#ifdef CONFIG_ARM64_TAGGED_ADDR
	/* Android 14 uses top-byte-ignore / MTE
	 * Tag is in bits 63:56 */
	return addr & 0x00FFFFFFFFFFFFFFULL;
#else
	return addr;
#endif
}

static void apex_capture_init_pc(void)
{
	struct task_struct *init_task;
	int cpu, i;

	rcu_read_lock();
	init_task = find_task_by_vpid(1);
	if (init_task)
		get_task_struct(init_task);
	rcu_read_unlock();

	if (!init_task)
		return;

	pr_err("APEX_FIX: init state=%ld cpu=%d\n",
		init_task->state, task_cpu(init_task));

	if (init_task->state == 0) {
		ipi_capture.target = init_task;
		ipi_capture.done = 0;
		cpu = task_cpu(init_task);

		smp_call_function_single(cpu, ipi_capture_fn, NULL, 1);

		if (!ipi_capture.done) {
			for_each_online_cpu(cpu) {
				if (cpu == smp_processor_id())
					continue;
				ipi_capture.done = 0;
				smp_call_function_single(cpu, ipi_capture_fn, NULL, 1);
				if (ipi_capture.done)
					break;
			}
		}

		if (ipi_capture.done) {
			pr_err("APEX_FIX: PC=0x%llx SP=0x%llx pstate=0x%llx\n",
				ipi_capture.pc, ipi_capture.sp, ipi_capture.pstate);
			/* Dump all registers */
			for (i = 0; i < 31; i++) {
				pr_err("APEX_FIX: x%d=0x%llx\n", i, ipi_capture.regs[i]);
			}

			/* Try to read memory at x0 (first arg) and x1 */
			for (i = 0; i <= 4; i++) {
				u64 addr = untag_addr(ipi_capture.regs[i]);
				if (addr > 0x10000 && addr < 0x7fffffffffff) {
					char buf[64];
					memset(buf, 0, sizeof(buf));
					if (!copy_from_user(buf, (void __user *)addr, 63)) {
						buf[63] = 0;
						pr_err("APEX_FIX: [x%d]=0x%llx -> \"%s\"\n",
							i, ipi_capture.regs[i], buf);
					} else {
						pr_err("APEX_FIX: [x%d]=0x%llx -> (unreadable)\n",
							i, ipi_capture.regs[i]);
					}
				}
			}
		}
	}

	put_task_struct(init_task);
}

static struct delayed_work apex_work;

static void apex_worker(struct work_struct *work)
{
	static int count = 0;

	pr_err("APEX_FIX: === CAPTURE %d ===\n", count);
	apex_capture_init_pc();

	count++;
	if (count < 5)
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

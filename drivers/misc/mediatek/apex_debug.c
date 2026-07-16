/*
 * apex_debug.c - Debug init busy-loop by capturing real-time user-space PC
 * and dumping the linked list that init is traversing.
 *
 * The loop is in libxml2's XML Catalog processing:
 *   while (node) {
 *     switch (node->type) {
 *       case 3: continue;  // skip
 *       case 5: if (xmlStrEqual(node->str, key)) goto found; break;
 *       case 8: if (prefix_match(node->str, key)) ...; break;
 *     }
 *     node = node->next;
 *   }
 *
 * If the linked list has a cycle, this loops forever.
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
#include <linux/smp.h>
#include <asm/ptrace.h>

extern unsigned long get_wchan(struct task_struct *p);

/* IPI capture state */
static struct {
	struct task_struct *target;
	u64 pc;
	u64 lr;
	u64 sp;
	u64 x21;  /* linked list node pointer */
	u64 x22;  /* search key string */
	u64 x25;  /* list head */
	u64 x27;  /* accumulator */
	int done;
} ipi_capture;

static void ipi_capture_fn(void *info)
{
	struct task_struct *tsk = ipi_capture.target;
	struct pt_regs *regs;

	if (!tsk || tsk != current)
		return;

	regs = task_pt_regs(tsk);
	if (regs) {
		ipi_capture.pc = regs->pc;
		ipi_capture.lr = regs->regs[30];
		ipi_capture.sp = regs->sp;
		ipi_capture.x21 = regs->regs[21];
		ipi_capture.x22 = regs->regs[22];
		ipi_capture.x25 = regs->regs[25];
		ipi_capture.x27 = regs->regs[27];
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
			pr_err("APEX_FIX: PC=0x%llx LR=0x%llx SP=0x%llx\n",
				ipi_capture.pc, ipi_capture.lr, ipi_capture.sp);
			pr_err("APEX_FIX: x21(node)=0x%llx x22(key)=0x%llx x25(head)=0x%llx x27=%llx\n",
				ipi_capture.x21, ipi_capture.x22,
				ipi_capture.x25, ipi_capture.x27);

			/* Dump the linked list to detect cycles.
			 * x21 is the current node. Each node starts with
			 * a next pointer at offset 0.
			 * Read up to 100 nodes from user space. */
			if (ipi_capture.x21 && ipi_capture.x21 > 0x1000) {
				u64 node = ipi_capture.x21;
				u64 addrs[100];
				int i, count = 0;
				int cycle_at = -1;

				for (i = 0; i < 100 && node > 0x1000; i++) {
					u64 next = 0;
					u32 type = 0;
					char str_buf[64] = {0};

					/* Read next pointer (offset 0) */
					if (copy_from_user(&next, (void __user *)node, 8))
						break;
					/* Read type (offset 0x18) */
					if (copy_from_user(&type, (void __user *)(node + 0x18), 4))
						break;

					addrs[i] = node;

					/* Read string pointer (offset 0x20) */
					u64 str_ptr = 0;
					if (copy_from_user(&str_ptr, (void __user *)(node + 0x20), 8))
						str_ptr = 0;
					if (str_ptr > 0x1000) {
						copy_from_user(str_buf, (void __user *)str_ptr, 63);
						str_buf[63] = 0;
					}

					/* Check for cycle */
					for (int j = 0; j < i; j++) {
						if (addrs[j] == node) {
							cycle_at = j;
							break;
						}
					}
					if (cycle_at >= 0) {
						pr_err("APEX_FIX: *** CYCLE DETECTED *** node[%d]=node[%d]=0x%llx type=%d str=\"%s\"\n",
							i, cycle_at, node, type, str_buf);
						break;
					}

					pr_err("APEX_FIX: node[%d]=0x%llx type=%d next=0x%llx str=\"%s\"\n",
						i, node, type, next, str_buf);

					node = next;
					count++;
				}
				if (cycle_at < 0)
					pr_err("APEX_FIX: traversed %d nodes, no cycle found\n", count);
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

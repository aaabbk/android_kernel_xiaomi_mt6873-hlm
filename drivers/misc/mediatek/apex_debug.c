/*
 * apex_debug.c - Track critical Android service lifecycle to diagnose
 * "stuck at first screen" (卡一屏) issue.
 *
 * Build: CONFIG_MTK_APEX_DEBUG=y
 * Watch:  dmesg | grep APEX
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/utsname.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/ptrace.h>

static const char * const apex_watch_bins[] = {
	"/system/bin/app_process",
	"/system/bin/app_process64",
	"surfaceflinger",
	"bootanim",
	"/system/bin/surfaceflinger",
	"/system/bin/bootanimation",
	"servicemanager",
	"hwservicemanager",
	"vndservicemanager",
	"system_server",
	"gatekeeperd",
	"keystore",
	"netd",
	"vold",
	NULL,
};

static int apex_watch_exec(const char *filename)
{
	const char * const *p;
	if (!filename)
		return 0;
	for (p = apex_watch_bins; *p; p++) {
		if (strstr(filename, *p))
			return 1;
	}
	return 0;
}

void apex_exec_hook(const char *filename)
{
	if (!filename)
		return;
	if (!apex_watch_exec(filename))
		return;
	pr_err("APEX_EXEC: pid=%d comm=%s exec='%s'\n",
		current->pid, current->comm, filename);
}
EXPORT_SYMBOL(apex_exec_hook);

static const char *apex_sig_name(int sig)
{
	static const char *names[] = {
		[0]="0", [1]="SIGHUP", [2]="SIGINT", [3]="SIGQUIT",
		[4]="SIGILL", [5]="SIGTRAP", [6]="SIGABRT", [7]="SIGBUS",
		[8]="SIGFPE", [9]="SIGKILL", [11]="SIGSEGV", [13]="SIGPIPE",
		[15]="SIGTERM", [26]="SIGVTALRM",
	};
	if (sig >= 0 && sig <= 26)
		return names[sig] ? names[sig] : "?";
	return "?";
}

void apex_do_exit_hook(long code)
{
	struct task_struct *t = current;
	struct pt_regs *regs;
	int is_signal = 0, sig = 0;

	if (t->flags & PF_KTHREAD)
		return;

	if (strncmp(t->comm, "surfaceflinger", 14) &&
	    strncmp(t->comm, "app_process", 11) &&
	    strncmp(t->comm, "zygote", 6) &&
	    strncmp(t->comm, "bootanim", 8) &&
	    strncmp(t->comm, "system_server", 13) &&
	    strncmp(t->comm, "init", 4) &&
	    strncmp(t->comm, "servicemanager", 14) &&
	    strncmp(t->comm, "hwservicemanager", 16) &&
	    strncmp(t->comm, "vold", 4) &&
	    strncmp(t->comm, "netd", 4))
		return;

	if (code > 0 && code < 0x80) {
		is_signal = 1;
		sig = (int)code;
	} else if (code == 0) {
		if (sigismember(&t->signal->shared_pending.signal, SIGKILL)) {
			is_signal = 1; sig = SIGKILL;
		} else if (sigismember(&t->signal->shared_pending.signal, SIGABRT)) {
			is_signal = 1; sig = SIGABRT;
		}
	}

	if (is_signal) {
		regs = task_pt_regs(t);
		pr_err("APEX_EXIT: pid=%d comm=%s KILLED BY SIG=%d(%s) code=0x%lx\n",
			t->pid, t->comm, sig, apex_sig_name(sig), code);
		if (regs && user_mode(regs)) {
			pr_err("APEX_EXIT:   PC=0x%llx SP=0x%llx pstate=0x%llx\n",
				regs->pc, regs->sp, regs->pstate);
			pr_err("APEX_EXIT:   x0=%016llx x1=%016llx x8=%016llx LR=%016llx\n",
				regs->regs[0], regs->regs[1],
				regs->regs[8], regs->regs[30]);
		}
	} else {
		int exit_status = (int)(code >> 8) & 0xff;
		pr_err("APEX_EXIT: pid=%d comm=%s normal exit(%d) code=0x%lx\n",
			t->pid, t->comm, exit_status, code);
	}
}
EXPORT_SYMBOL(apex_do_exit_hook);

static struct timer_list apex_watchdog;
static int apex_watchdog_fired;

static void apex_watchdog_fn(struct timer_list *t)
{
	struct task_struct *task;
	int sf = 0, zy = 0, ba = 0, ss = 0;

	rcu_read_lock();
	for_each_process(task) {
		if (strncmp(task->comm, "surfaceflinger", 14) == 0) sf++;
		else if (strncmp(task->comm, "main", 4) == 0 &&
			 task->parent &&
			 strncmp(task->parent->comm, "zygote", 6) == 0) zy++;
		else if (strncmp(task->comm, "bootanim", 8) == 0) ba++;
		else if (strncmp(task->comm, "system_server", 13) == 0) ss++;
	}
	rcu_read_unlock();

	pr_err("APEX_WDT: [%lus] surfaceflinger=%d zygote_children=%d bootanim=%d system_server=%d\n",
		jiffies_to_msecs(jiffies) / 1000, sf, zy, ba, ss);

	if (!sf && !apex_watchdog_fired && jiffies_to_msecs(jiffies) > 30000) {
		apex_watchdog_fired = 1;
		pr_err("APEX_WDT: WARNING: 30s reached, surfaceflinger NOT running!\n");
		pr_err("APEX_WDT: Dumping all userspace processes:\n");
		rcu_read_lock();
		for_each_process(task) {
			if (!(task->flags & PF_KTHREAD) && task->mm)
				pr_err("APEX_WDT:   pid=%d comm=%s\n",
					task->pid, task->comm);
		}
		rcu_read_unlock();
	}

	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
}

static int __init apex_debug_init(void)
{
	pr_err("APEX: apex_debug loaded. kernel=%s\n", utsname()->release);
	pr_err("APEX: tracking exec+exit of: zygote/surfaceflinger/bootanim/...\n");
	timer_setup(&apex_watchdog, apex_watchdog_fn, 0);
	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
	return 0;
}
late_initcall(apex_debug_init);

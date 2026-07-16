/*
 * apex_debug.c - Capture the REAL fatal signal & crash PC that ramoops misses.
 *
 * Problem diagnosis (resolved):
 *   - SF_DEBUG hooked do_exit(), but the do_exit(0) that fires is the
 *     debuggerd "pseudothread" (bionic's tombstone collector) AFTER it
 *     finishes writing the tombstone. Its code=0 was misreported as
 *     "signal 0". The real crash signal/PC of the main process was
 *     overwritten and never captured.
 *   - Solution: hook the signal-delivery path (do_send_sig_info), which
 *     runs BEFORE the signal handler / debuggerd pseudothread. There we
 *     can see the true fatal signal and the faulting pt_regs.
 *
 * Two hooks:
 *   1. apex_signal_hook()   - in do_send_sig_info(): log every fatal
 *      signal at delivery time with the target's current pt_regs.
 *   2. apex_do_exit_hook()  - in do_exit(): log exit code correctly,
 *      distinguishing signal-killed (code < 0x80) from exit_group
 *      (code >= 0x80 << 8) from the debuggerd pseudothread (code==0,
 *      comm contains pseudothread). FIXES the "signal 0" misreport.
 *
 * Wiring: apex_signal_hook is called from kernel/signal.c::do_send_sig_info.
 *         apex_do_exit_hook is called from kernel/exit.c::do_exit (existing
 *         SF_DEBUG block, corrected logic).
 *
 * Watch:  dmesg | grep APEX
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/signal_types.h>
#include <linux/utsname.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/ptrace.h>

/* ============================================================
 * Part 1: Signal-delivery hook — captures the REAL crash cause
 * ============================================================
 * Called from do_send_sig_info() in kernel/signal.c, BEFORE the
 * signal handler runs. This is the earliest point where we can
 * correlate "signal N sent to process X" with X's current regs.
 *
 * For synchronous signals (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP),
 * the target task's pt_regs contains the faulting PC — THIS is
 * the real crash PC that ramoops/SF_DEBUG never see.
 */

static const char *apex_sig_name(int sig)
{
	static const char *names[] = {
		[0]  = "0",
		[1]  = "SIGHUP",  [2]  = "SIGINT",  [3]  = "SIGQUIT",
		[4]  = "SIGILL",  [5]  = "SIGTRAP", [6]  = "SIGABRT",
		[7]  = "SIGBUS",  [8]  = "SIGFPE",  [9]  = "SIGKILL",
		[10] = "SIGUSR1", [11] = "SIGSEGV", [12] = "SIGUSR2",
		[13] = "SIGPIPE", [14] = "SIGALRM", [15] = "SIGTERM",
		[16] = "SIGSTKFLT",[17] = "SIGCHLD",[18] = "SIGCONT",
		[19] = "SIGSTOP", [20] = "SIGTSTP", [21] = "SIGTTIN",
		[22] = "SIGTTOU", [23] = "SIGURG",  [24] = "SIGXCPU",
		[25] = "SIGXFSZ", [26] = "SIGVTALRM",[27] = "SIGPROF",
		[28] = "SIGWINCH",[29] = "SIGIO",   [30] = "SIGPWR",
		[31] = "SIGSYS",
	};
	if (sig >= 0 && sig <= 31)
		return names[sig];
	return "?";
}

/* Fatal signals that kill a process */
static int apex_is_fatal(int sig)
{
	switch (sig) {
	case SIGKILL:
	case SIGABRT:
	case SIGSEGV:
	case SIGBUS:
	case SIGFPE:
	case SIGILL:
	case SIGSYS:
	case SIGQUIT:
	case SIGTERM:
	case SIGXCPU:
	case SIGXFSZ:
		return 1;
	default:
		return 0;
	}
}

/* Match process names we care about. NULL first entry = match all. */
static const char * const apex_watch[] = {
	"surfaceflinger",
	"android.hardwar",	/* android.hardware.* (truncated) */
	"keymaster",
	"gatekeeperd",
	"init",
	"linker",
	"linker64",
	"zygote",
	"zygote64",
	"servicemanager",
	"hwservicemanager",
	"vndservicemanag",
	"vold",
	"vendor.mediatek",
	"cameraserver",
	"mediadrmserver",
	"mediaserver",
	"netd",
	NULL,
};

static int apex_comm_match(const char *comm)
{
	const char * const *p;
	size_t len;
	if (!apex_watch[0])
		return 1;
	for (p = apex_watch; *p; p++) {
		len = strlen(*p);
		if (strncmp(comm, *p, len) == 0)
			return 1;
	}
	return 0;
}

/* Main signal-delivery hook. Called from do_send_sig_info().
 * Signature matches: int sig, struct siginfo *info, struct task_struct *p
 */
void apex_signal_hook(int sig, struct siginfo *info, struct task_struct *p)
{
	struct pt_regs *regs;
	unsigned long flags;
	const char *how;

	if (!p)
		return;

	/* Only fatal signals, only userspace targets */
	if (!apex_is_fatal(sig))
		return;
	if (p->flags & PF_KTHREAD)
		return;
	if (!apex_comm_match(p->comm))
		return;

	/* Try to get the target's regs. If p == current, use current_regs.
	 * If p != current, we can only safely read p without locking for
	 * regs in 4.14 (task_pt_regs is computed from kernel stack top). */
	regs = task_pt_regs(p);
	if (!regs)
		return;

	/* Determine delivery source — MUST check special kernel sentinel
	 * values BEFORE touching info, or we dereference (void*)1/2. */
	if (info == SEND_SIG_PRIV)
		how = "from-kernel(priv)";
	else if (info == SEND_SIG_FORCED)
		how = "forced";
	else if (!info)
		how = "null";
	else if (SI_FROMUSER(info))
		how = "from-user";
	else
		how = "from-kernel";

	pr_err("APEX_SIG: pid=%d tgid=%d comm=%s <-- SIG=%d(%s) %s\n",
		p->pid, p->tgid, p->comm, sig, apex_sig_name(sig), how);

	/* For synchronous faults (SEGV/BUS/FPE/ILL/TRAP), si_addr has
	 * the faulting address. This is the REAL crash address.
	 * Guard against SEND_SIG_PRIV/FORCED sentinels. */
	if (info && info != SEND_SIG_PRIV && info != SEND_SIG_FORCED &&
	    (sig == SIGSEGV || sig == SIGBUS || sig == SIGFPE ||
	     sig == SIGILL || sig == SIGTRAP)) {
		pr_err("APEX_SIG:   fault_addr=0x%llx si_code=0x%x\n",
			(unsigned long long)info->si_addr, info->si_code);
	}

	/* Dump the target's pt_regs — THIS is the real crash PC */
	if (user_mode(regs)) {
		pr_err("APEX_SIG:   PC=0x%llx SP=0x%llx pstate=0x%llx [USER]\n",
			regs->pc, regs->sp, regs->pstate);
	} else {
		pr_err("APEX_SIG:   PC=0x%llx [KERNEL, target not in userspace]\n",
			regs->pc);
	}
	pr_err("APEX_SIG:   x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
		regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);
	pr_err("APEX_SIG:   x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
		regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7]);
	pr_err("APEX_SIG:   x8=%016llx x9=%016llx x16=%016llx x17=%016llx\n",
		regs->regs[8], regs->regs[9], regs->regs[16], regs->regs[17]);
	pr_err("APEX_SIG:   x18=%016llx x19=%016llx x20=%016llx x21=%016llx\n",
		regs->regs[18], regs->regs[19], regs->regs[20], regs->regs[21]);
	pr_err("APEX_SIG:   x22=%016llx x23=%016llx x24=%016llx x25=%016llx\n",
		regs->regs[22], regs->regs[23], regs->regs[24], regs->regs[25]);
	pr_err("APEX_SIG:   x26=%016llx x27=%016llx x28=%016llx x29=%016llx LR=%016llx\n",
		regs->regs[26], regs->regs[27], regs->regs[28],
		regs->regs[29], regs->regs[30]);

	/* For SEGV/BUS, also dump FAR_EL1 if target == current */
	if (p == current && (sig == SIGSEGV || sig == SIGBUS ||
			     sig == SIGFPE || sig == SIGILL)) {
		u64 far, esr;
		asm volatile("mrs %0, far_el1" : "=r"(far));
		asm volatile("mrs %0, esr_el1" : "=r"(esr));
		pr_err("APEX_SIG:   FAR_EL1=0x%llx ESR_EL1=0x%llx\n", far, esr);
	}
}
EXPORT_SYMBOL(apex_signal_hook);

/* ============================================================
 * Part 2: Corrected do_exit hook — fixes the "signal 0" misreport
 * ============================================================
 * The existing SF_DEBUG in do_exit() reported "killed by signal 0"
 * because code=0 (the debuggerd pseudothread's _exit(0)) matched
 * code < 0x100. This is WRONG:
 *
 *   do_exit() code encoding in Linux:
 *     - signal-killed:  code = signal_number (1..31), so 0 < code < 0x80
 *     - exit_group(n):  code = (n << 8), so code >= 0x100
 *     - _exit(0):       code = 0 (the pseudothread or clean exit)
 *
 *   code == 0 is NOT "signal 0" — it's a clean exit_group(0) or _exit(0).
 *   There is no "signal 0" in Linux; signals start at 1.
 *
 * Called from do_exit() in kernel/exit.c, replacing the SF_DEBUG block.
 */
void apex_do_exit_hook(long code)
{
	struct task_struct *t = current;
	struct pt_regs *regs = task_pt_regs(t);
	int is_signal = 0;
	int sig = 0;
	int is_pseudothread = 0;

	if (t->flags & PF_KTHREAD)
		return;
	if (!apex_comm_match(t->comm))
		return;

	/* Detect the debuggerd pseudothread — it does _exit(0) after
	 * writing the tombstone, which is NOT a crash. */
	if (strstr(t->comm, "pseudothread") ||
	    strstr(t->comm, "debuggerd") ||
	    (code == 0 && (sigismember(&t->signal->shared_pending.signal, SIGABRT) ||
			   sigismember(&t->signal->shared_pending.signal, SIGSEGV)))) {
		is_pseudothread = 1;
	}

	/* Correct signal detection:
	 * - code in 1..31 (but NOT 0) = killed by that signal
	 * - code >= 0x100 = exit_group, NOT a signal death
	 * - code == 0 = clean exit (likely the pseudothread) */
	if (code > 0 && code < 0x80) {
		is_signal = 1;
		sig = (int)code;
	} else if (code >= 0x100) {
		is_signal = 0;	/* exit_group(n) — normal exit */
	} else {
		/* code == 0: check if a fatal signal is pending — if so,
		 * the process was killed but do_exit got 0 (rare in 4.14).
		 * Otherwise it's a genuine clean exit (pseudothread). */
		if (sigismember(&t->signal->shared_pending.signal, SIGKILL)) {
			is_signal = 1; sig = SIGKILL;
		} else if (sigismember(&t->signal->shared_pending.signal, SIGABRT)) {
			is_signal = 1; sig = SIGABRT;
		} else if (sigismember(&t->signal->shared_pending.signal, SIGSEGV)) {
			is_signal = 1; sig = SIGSEGV;
		}
	}

	if (is_pseudothread) {
		pr_err("APEX_EXIT: pid=%d comm=%s code=0x%lx [PSEUDOTHREAD] "
			"tombstone collector exiting — NOT a crash\n",
			t->pid, t->comm, code);
		return;
	}

	if (is_signal) {
		pr_err("APEX_EXIT: pid=%d tgid=%d comm=%s code=0x%lx "
			"KILLED BY SIG=%d(%s)\n",
			t->pid, t->tgid, t->comm, code,
			sig, apex_sig_name(sig));
	} else {
		int exit_status = (int)(code >> 8) & 0xff;
		pr_err("APEX_EXIT: pid=%d tgid=%d comm=%s code=0x%lx "
			"normal exit_group(%d)\n",
			t->pid, t->tgid, t->comm, code, exit_status);
	}

	/* Always dump regs for watched processes — if the death was
	 * synchronous (SEGV/BUS), regs->pc is the faulting instruction */
	if (regs && user_mode(regs)) {
		pr_err("APEX_EXIT:   PC=0x%llx SP=0x%llx pstate=0x%llx\n",
			regs->pc, regs->sp, regs->pstate);
		pr_err("APEX_EXIT:   x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
			regs->regs[0], regs->regs[1],
			regs->regs[2], regs->regs[3]);
		pr_err("APEX_EXIT:   x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
			regs->regs[4], regs->regs[5],
			regs->regs[6], regs->regs[7]);
		pr_err("APEX_EXIT:   x8=%016llx x16=%016llx x17=%016llx LR=%016llx\n",
			regs->regs[8], regs->regs[16],
			regs->regs[17], regs->regs[30]);
	}

	/* Dump pending signal set for diagnosis */
	{
		sigset_t *s = &t->signal->shared_pending.signal;
		pr_err("APEX_EXIT:   shared_pending sig[0]=0x%lx sig[1]=0x%lx\n",
			s->sig[0], s->sig[1]);
	}
}
EXPORT_SYMBOL(apex_do_exit_hook);

static int __init apex_debug_init(void)
{
	pr_err("APEX: apex_debug loaded. kernel=%s\n", utsname()->release);
	pr_err("APEX: hooks: apex_signal_hook (do_send_sig_info), "
		"apex_do_exit_hook (do_exit)\n");
	pr_err("APEX: watching fatal signals on: surfaceflinger/hardware/"
		"keymaster/init/zygote/...\n");
	pr_err("APEX: grep for APEX_SIG (signal delivery) and "
		"APEX_EXIT (process exit) in dmesg\n");
	return 0;
}
late_initcall(apex_debug_init);

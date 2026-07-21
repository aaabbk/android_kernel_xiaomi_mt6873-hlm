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
#include <linux/stacktrace.h>
#include <linux/sched/debug.h>
#include <linux/kallsyms.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include <linux/of.h>
#include <linux/signal_types.h>
#include <asm/ptrace.h>
#include <mt-plat/mtk_boot.h>

/* Kernel command line is declared as extern char *saved_command_line
 * in <linux/init.h> (included transitively via <linux/module.h>) */

/* Partition lookup from MTK partition driver */
extern struct hd_struct *get_part(const char *name);

/* ============================================================
 * Watch list for exec monitoring
 * ============================================================ */
static const char * const apex_watch_bins[] = {
	"app_process",
	"zygote",
	"surfaceflinger",
	"bootanim",
	"system_server",
	"servicemanager",
	"hwservicemanager",
	"vndservicemanager",
	"vold",
	"netd",
	"gatekeeperd",
	"keystore",
	"bpfloader",
	"bootctrl",
	"secilc",
	"apexd",
	"linkerconfig",
	"keystore2",
	"init",
	"keymaster",
	"beanpod",
	"teei_daemon",
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

/* Track keymaster HAL pid for precise stack dumps.
 * Multiple instances may start over time; keep last 4 pids. */
#define APEX_KM_PID_MAX 4
static atomic_t apex_km_pids[APEX_KM_PID_MAX];
static int apex_km_pid_count = 0;

static void apex_record_km_pid(pid_t pid, const char *filename)
{
	int i;
	bool is_km = false;

	if (strstr(filename, "keymaster") || strstr(filename, "beanpod"))
		is_km = true;

	if (!is_km)
		return;

	/* Check if pid already recorded */
	for (i = 0; i < apex_km_pid_count && i < APEX_KM_PID_MAX; i++) {
		if (atomic_read(&apex_km_pids[i]) == pid)
			return;
	}

	/* Record new pid */
	if (apex_km_pid_count < APEX_KM_PID_MAX) {
		atomic_set(&apex_km_pids[apex_km_pid_count], pid);
		apex_km_pid_count++;
	} else {
		/* Overwrite oldest slot */
		atomic_set(&apex_km_pids[0], pid);
	}

	pr_err("APEX_KM: keymaster HAL started pid=%d exec='%s' (tracked: %d)\n",
		pid, filename, apex_km_pid_count);
}

static bool apex_is_km_pid(pid_t pid)
{
	int i;
	for (i = 0; i < apex_km_pid_count && i < APEX_KM_PID_MAX; i++) {
		if (atomic_read(&apex_km_pids[i]) == pid)
			return true;
	}
	return false;
}

/* ============================================================
 * Hook 1: exec tracking
 * ============================================================ */
void apex_exec_hook(const char *filename)
{
	if (!filename)
		return;

	/* Track keymaster HAL pid */
	apex_record_km_pid(current->pid, filename);

	/* Always log watched binaries */
	if (apex_watch_exec(filename)) {
		pr_err("APEX_EXEC: pid=%d comm=%s exec='%s'\n",
			current->pid, current->comm, filename);
		return;
	}

	/* Also log ALL exec from pid 1 (init) or children of pid 1
	 * to trace action chain. Only for standard binary paths. */
	if (current->pid == 1 || (current->parent && current->parent->pid == 1)) {
		if (strstr(filename, "/system/bin/") ||
		    strstr(filename, "/vendor/bin/") ||
		    strstr(filename, "/system/xbin/")) {
			pr_err("APEX_EXEC_INIT: pid=%d ppid=%d exec='%s'\n",
				current->pid,
				current->parent ? current->parent->pid : 0,
				filename);
		}
	}
}
EXPORT_SYMBOL(apex_exec_hook);

/* Hook 1b: file open tracking for keymaster HAL.
 * Logs all file opens by tracked keymaster pids to see which
 * devices/files it tries to open during initialization. */
void apex_open_hook(const char *filename, int fd)
{
	if (apex_is_km_pid(current->pid)) {
		if (fd >= 0)
			pr_err("APEX_KM: open OK pid=%d comm=%s file='%s' fd=%d\n",
				current->pid, current->comm, filename, fd);
		else
			pr_err("APEX_KM: open FAIL pid=%d comm=%s file='%s' err=%d\n",
				current->pid, current->comm, filename, fd);
	}
}
EXPORT_SYMBOL(apex_open_hook);

/* Forward declaration - defined later, used by exit hook */
static void apex_dump_task_full(struct task_struct *task);

/* ============================================================
 * Hook 2: exit tracking
 * ============================================================ */
void apex_do_exit_hook(long code)
{
	struct task_struct *t = current;

	if (t->flags & PF_KTHREAD)
		return;

	/* Precise keymaster HAL exit tracking by pid */
	if (apex_is_km_pid(t->pid)) {
		if (code > 0 && code < 0x80) {
			pr_err("APEX_KM: *** keymaster HAL CRASHED *** pid=%d comm=%s signal(%d)\n",
				t->pid, t->comm, (int)code);
		} else {
			pr_err("APEX_KM: keymaster HAL EXITED pid=%d comm=%s code=%ld\n",
				t->pid, t->comm, code);
		}
		/* Dump kernel stack on exit to see what it was doing */
		pr_err("APEX_KM: exit stack for pid=%d:\n", t->pid);
		apex_dump_task_full(t);
	}

	if (strncmp(t->comm, "surfaceflinger", 14) &&
	    strncmp(t->comm, "app_process", 11) &&
	    strncmp(t->comm, "zygote", 6) &&
	    strncmp(t->comm, "bootanim", 8) &&
	    strncmp(t->comm, "system_server", 13) &&
	    strncmp(t->comm, "init", 4) &&
	    strncmp(t->comm, "servicemanager", 14) &&
	    strncmp(t->comm, "hwservicemanager", 16) &&
	    strncmp(t->comm, "vold", 4) &&
	    strncmp(t->comm, "netd", 4) &&
	    strncmp(t->comm, "bpfloader", 9) &&
	    strncmp(t->comm, "bootctrl", 8) &&
	    strncmp(t->comm, "secilc", 6) &&
	    strncmp(t->comm, "apexd", 5) &&
	    strncmp(t->comm, "linkerconfig", 12) &&
	    strncmp(t->comm, "keystore2", 9) &&
	    strncmp(t->comm, "android.hardwar", 15) &&  /* HAL services */
	    strncmp(t->comm, "vendor.xiaomi.h", 15) &&  /* xiaomi HAL */
	    strncmp(t->comm, "vendor.mediatek", 15) &&  /* MTK HAL */
	    strncmp(t->comm, "vendor.microtru", 15) &&  /* MicroTrust */
	    strncmp(t->comm, "gpuservice", 10) &&
	    strncmp(t->comm, "teei_daemon", 11))
		return;

	if (code > 0 && code < 0x80) {
		/* Killed by signal: code == signal number */
		pr_err("APEX_EXIT: pid=%d comm=%s fatal signal(%d)\n",
			t->pid, t->comm, (int)code);
	} else {
		/* Normal exit: extract user exit status */
		int exit_status = (int)(code >> 8) & 0xff;
		pr_err("APEX_EXIT: pid=%d comm=%s normal exit(%d)\n",
			t->pid, t->comm, exit_status);
	}
}
EXPORT_SYMBOL(apex_do_exit_hook);

/* ============================================================
 * Hook 3: signal delivery tracking via kprobe
 *
 * Captures fatal signals (SIGSEGV, SIGABRT, SIGKILL, etc.) delivered
 * to userspace processes. This helps identify WHY a process crashed
 * even without logcat/tombstone.
 *
 * do_send_sig_info(int sig, struct siginfo *info, struct task_struct *p, bool group)
 *   - arg0 (regs->regs[0]): signal number
 *   - arg2 (regs->regs[2]): target task_struct pointer
 *
 * force_sig_info(int sig, struct siginfo *info, struct task_struct *t)
 *   - arg0 (regs->regs[0]): signal number
 *   - arg2 (regs->regs[2]): target task_struct pointer
 * ============================================================ */

static int apex_is_signal_watch_target(struct task_struct *t)
{
	if (!t || (t->flags & PF_KTHREAD))
		return 0;
	/* Watch all HAL services and key processes */
	if (!strncmp(t->comm, "android.hardwar", 15)) return 1;
	if (!strncmp(t->comm, "vendor.xiaomi.h", 15)) return 1;
	if (!strncmp(t->comm, "vendor.mediatek", 15)) return 1;
	if (!strncmp(t->comm, "vendor.microtru", 15)) return 1;
	if (!strncmp(t->comm, "surfaceflinger", 14)) return 1;
	if (!strncmp(t->comm, "bootanim", 8)) return 1;
	if (!strncmp(t->comm, "vold", 4)) return 1;
	if (!strncmp(t->comm, "init", 4) && t->pid <= 2) return 1;
	if (!strncmp(t->comm, "app_process", 11)) return 1;
	if (!strncmp(t->comm, "system_server", 13)) return 1;
	if (!strncmp(t->comm, "keystore2", 9)) return 1;
	if (!strncmp(t->comm, "teei_daemon", 11)) return 1;
	if (!strncmp(t->comm, "gpuservice", 10)) return 1;
	return 0;
}

static const char *apex_sig_name(int sig)
{
	switch (sig) {
	case 1:  return "SIGHUP";
	case 2:  return "SIGINT";
	case 3:  return "SIGQUIT";
	case 4:  return "SIGILL";
	case 5:  return "SIGTRAP";
	case 6:  return "SIGABRT";
	case 7:  return "SIGBUS";
	case 8:  return "SIGFPE";
	case 9:  return "SIGKILL";
	case 10: return "SIGUSR1";
	case 11: return "SIGSEGV";
	case 12: return "SIGUSR2";
	case 13: return "SIGPIPE";
	case 14: return "SIGALRM";
	case 15: return "SIGTERM";
	case 17: return "SIGCHLD";
	case 19: return "SIGSTOP";
	case 24: return "SIGXCPU";
	case 25: return "SIGXFSZ";
	default: return "OTHER";
	}
}

/* kprobe pre_handler for do_send_sig_info */
static int apex_kp_do_send_sig_pre(struct kprobe *p, struct pt_regs *regs)
{
	int sig;
	struct task_struct *target;

	sig = (int)regs->regs[0];
	target = (struct task_struct *)regs->regs[2];

	if (!apex_is_signal_watch_target(target))
		return 0;

	/* Only log fatal signals */
	if (sig < 3 || sig == 17 || sig == 19)
		return 0;

	pr_err("APEX_SIG: do_send_sig pid=%d comm=%s sig=%d(%s) from pid=%d comm=%s\n",
		target->pid, target->comm, sig, apex_sig_name(sig),
		current->pid, current->comm);
	return 0;
}

/* One-shot guard: dump full crash context only once per process.
 * Avoids log flooding when SIGSEGV loops in ART runtime. */
static atomic_t apex_segv_dumped = ATOMIC_INIT(0);

/* kprobe pre_handler for force_sig_info
 *
 * force_sig_info(int sig, struct siginfo *info, struct task_struct *t)
 *   arg0 (regs->regs[0]): signal number
 *   arg1 (regs->regs[1]): siginfo pointer (may be SEND_SIG_PRIV/FORCED)
 *   arg2 (regs->regs[2]): target task_struct pointer
 *
 * For SIGSEGV/SIGBUS/SIGFPE/SIGILL, we dump:
 *   - si_code (SEGV_MAPERR=1, SEGV_ACCERR=2)
 *   - si_addr (faulting virtual address)
 *   - target's user-mode pt_regs (PC, LR, SP, x0-x29)
 *   - FAR_EL1 / ESR_EL1 (if target == current)
 */
static int apex_kp_force_sig_pre(struct kprobe *p, struct pt_regs *regs)
{
	int sig;
	struct siginfo *info;
	struct task_struct *target;
	struct pt_regs *target_regs;
	int first_crash;

	sig = (int)regs->regs[0];
	info = (struct siginfo *)regs->regs[1];
	target = (struct task_struct *)regs->regs[2];

	if (!apex_is_signal_watch_target(target))
		return 0;

	/* Always log the signal (compact, one line) */
	pr_err("APEX_SIG: force_sig pid=%d comm=%s sig=%d(%s) from pid=%d comm=%s\n",
		target->pid, target->comm, sig, apex_sig_name(sig),
		current->pid, current->comm);

	/* For SIGSEGV/SIGBUS/SIGFPE/SIGILL, dump full crash context ONCE.
	 * ART often loops on the same SIGSEGV, so we only dump details
	 * the first time to avoid log flooding. */
	if (sig != 11 && sig != 7 && sig != 8 && sig != 4 && sig != 5)
		return 0;

	first_crash = atomic_cmpxchg(&apex_segv_dumped, 0, 1);
	if (first_crash)
		return 0;  /* already dumped details for this crash */

	pr_err("APEX_SIG: === CRASH CONTEXT DUMP (one-shot) ===\n");

	/* si_code and si_addr from siginfo (guard against sentinel values) */
	if (info && info != SEND_SIG_PRIV && info != SEND_SIG_FORCED) {
		pr_err("APEX_SIG:   si_code=0x%x si_addr=0x%llx\n",
			info->si_code,
			(unsigned long long)info->si_addr);
		/* Decode si_code for SIGSEGV */
		if (sig == 11) {
			switch (info->si_code) {
			case 1: pr_err("APEX_SIG:   SEGV_MAPERR (address not mapped)\n"); break;
			case 2: pr_err("APEX_SIG:   SEGV_ACCERR (invalid permissions)\n"); break;
			default: pr_err("APEX_SIG:   unknown si_code=%d\n", info->si_code); break;
			}
		}
	} else {
		pr_err("APEX_SIG:   info=%p (sentinel, no si_addr)\n", info);
	}

	/* Dump target's user-mode pt_regs — THIS is the real crash PC.
	 * task_pt_regs() computes from the top of the kernel stack. */
	target_regs = task_pt_regs(target);
	if (!target_regs) {
		pr_err("APEX_SIG:   target_regs=NULL (cannot dump)\n");
		return 0;
	}

	if (user_mode(target_regs)) {
		pr_err("APEX_SIG:   PC=0x%llx SP=0x%llx pstate=0x%llx [USER]\n",
			target_regs->pc, target_regs->sp, target_regs->pstate);
	} else {
		pr_err("APEX_SIG:   PC=0x%llx [KERNEL, target not in userspace]\n",
			target_regs->pc);
	}

	/* Dump key registers for backtrace analysis:
	 * x0-x7: argument registers
	 * x16-x17: intra-procedure-call scratch (IP0/IP1)
	 * x29: frame pointer (FP)
	 * x30: link register (LR) — return address
	 */
	pr_err("APEX_SIG:   x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
		target_regs->regs[0], target_regs->regs[1],
		target_regs->regs[2], target_regs->regs[3]);
	pr_err("APEX_SIG:   x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
		target_regs->regs[4], target_regs->regs[5],
		target_regs->regs[6], target_regs->regs[7]);
	pr_err("APEX_SIG:   x8=%016llx x9=%016llx x16=%016llx x17=%016llx\n",
		target_regs->regs[8], target_regs->regs[9],
		target_regs->regs[16], target_regs->regs[17]);
	pr_err("APEX_SIG:   x18=%016llx x19=%016llx x20=%016llx x21=%016llx\n",
		target_regs->regs[18], target_regs->regs[19],
		target_regs->regs[20], target_regs->regs[21]);
	pr_err("APEX_SIG:   x22=%016llx x23=%016llx x24=%016llx x25=%016llx\n",
		target_regs->regs[22], target_regs->regs[23],
		target_regs->regs[24], target_regs->regs[25]);
	pr_err("APEX_SIG:   x26=%016llx x27=%016llx x28=%016llx FP=%016llx LR=%016llx\n",
		target_regs->regs[26], target_regs->regs[27],
		target_regs->regs[28], target_regs->regs[29],
		target_regs->regs[30]);

	/* Read the REAL fault address and ESR from target's thread_struct.
	 *
	 * CRITICAL: Do NOT read FAR_EL1/ESR_EL1 directly!
	 * __do_user_fault() saves the real exception info into
	 *   tsk->thread.fault_address  -> faulting virtual address (FAR)
	 *   tsk->thread.fault_code     -> exception syndrome (ESR)
	 * BEFORE calling force_sig_info()->this kprobe fires.
	 *
	 * Reading ESR_EL1 directly gets the kprobe's OWN BRK #4 syndrome
	 * (BRK64_ESR_KPROBES=0x4, ESR=0xf2000004) because the kprobe at
	 * force_sig_info replaces its first instruction with brk #4.
	 * That BRK overwrites ESR_EL1 with the BRK syndrome, NOT the
	 * original data abort ESR.
	 *
	 * thread.fault_code is valid for SEGV/BUS/FPE/ILL (synchronous faults).
	 */
	{
		u64 far, esr;
		u32 ec, il, iss;
		far = target->thread.fault_address;
		esr = target->thread.fault_code;
		pr_err("APEX_SIG:   fault_addr=0x%llx ESR=0x%llx [from thread_struct]\n",
			far, esr);
		/* Decode ESR: EC=bits[31:26], IL=bit[25], ISS=bits[24:0] */
		ec = (u32)((esr >> 26) & 0x3f);
		il = (u32)((esr >> 25) & 1);
		iss = (u32)(esr & 0x1ffffff);
		pr_err("APEX_SIG:   EC=0x%02x IL=%d ISS=0x%05x\n", ec, il, iss);
		/* Decode common EC values */
		if (ec == 0x24 || ec == 0x25)
			pr_err("APEX_SIG:   => Data Abort (DABT)\n");
		else if (ec == 0x20 || ec == 0x21)
			pr_err("APEX_SIG:   => Instruction Abort (IABT)\n");
		else if (ec == 0x3c || ec == 0x35)
			pr_err("APEX_SIG:   => BRK (debug) — WARNING: stale ESR!\n");
		/* Decode DFSC for data aborts (bits[5:0] of ISS) */
		if (ec == 0x24 || ec == 0x25) {
			u32 dfsc = iss & 0x3f;
			const char *dfsc_name = "unknown";
			switch (dfsc) {
			case 0x04: dfsc_name = "level 0 translation fault"; break;
			case 0x05: dfsc_name = "level 1 translation fault"; break;
			case 0x06: dfsc_name = "level 2 translation fault"; break;
			case 0x07: dfsc_name = "level 3 translation fault"; break;
			case 0x0c: dfsc_name = "level 0 access flag fault"; break;
			case 0x0d: dfsc_name = "level 1 access flag fault"; break;
			case 0x0e: dfsc_name = "level 2 access flag fault"; break;
			case 0x0f: dfsc_name = "level 3 access flag fault"; break;
			case 0x14: dfsc_name = "level 0 permission fault"; break;
			case 0x15: dfsc_name = "level 1 permission fault"; break;
			case 0x16: dfsc_name = "level 2 permission fault"; break;
			case 0x17: dfsc_name = "level 3 permission fault"; break;
			}
			pr_err("APEX_SIG:   DFSC=0x%02x (%s)\n", dfsc, dfsc_name);
		}
	}

	/* Dump the VMA (virtual memory area) containing the crash PC.
	 * This tells us which .so library the crash is in.
	 * We iterate the target's mm->mmap VMA list and find the one
	 * containing target_regs->pc. Also dump a few VMAs around it
	 * for context (libraries loaded nearby). */
	if (target->mm) {
		struct vm_area_struct *vma;
		u64 crash_pc = target_regs->pc;
		int vma_count = 0;
		struct vm_area_struct *crash_vma = NULL;

		/* Find the VMA containing crash_pc */
		down_read(&target->mm->mmap_sem);
		for (vma = target->mm->mmap; vma; vma = vma->vm_next) {
			if (crash_pc >= vma->vm_start && crash_pc < vma->vm_end) {
				crash_vma = vma;
				break;
			}
		}

		if (crash_vma) {
			const char *vma_name = (crash_vma->vm_file &&
				crash_vma->vm_file->f_path.dentry) ?
				(const char *)crash_vma->vm_file->f_path.dentry->d_name.name :
				"[anon]";
			pr_err("APEX_SIG:   [CRASH VMA] 0x%016lx-0x%016lx %08lx %s\n",
				crash_vma->vm_start, crash_vma->vm_end,
				crash_vma->vm_flags, vma_name);
			pr_err("APEX_SIG:   crash PC offset in VMA = 0x%llx\n",
				crash_pc - crash_vma->vm_start);
		} else {
			pr_err("APEX_SIG:   [CRASH PC 0x%llx NOT in any VMA]\n", crash_pc);
		}

		/* Dump ALL executable VMAs (libraries) for full picture.
		 * Limit to first 80 to avoid log flooding. */
		pr_err("APEX_SIG:   === executable VMAs (libraries) ===\n");
		for (vma = target->mm->mmap; vma && vma_count < 80; vma = vma->vm_next) {
			const char *name = "[anon]";
			if (vma->vm_file && vma->vm_file->f_path.dentry)
				name = (const char *)vma->vm_file->f_path.dentry->d_name.name;
			/* Only dump executable or file-backed VMAs */
			if ((vma->vm_flags & VM_EXEC) || vma->vm_file) {
				/* Mark the crash VMA with >>> */
				pr_err("APEX_SIG:   %s 0x%016lx-0x%016lx %08lx %s\n",
					(vma == crash_vma) ? ">>>" : "   ",
					vma->vm_start, vma->vm_end,
					vma->vm_flags, name);
				vma_count++;
			}
		}
		pr_err("APEX_SIG:   === %d executable/file VMAs dumped ===\n", vma_count);
		up_read(&target->mm->mmap_sem);
	} else {
		pr_err("APEX_SIG:   target->mm=NULL (kernel thread or exiting)\n");
	}

	pr_err("APEX_SIG: === crash context dump done ===\n");
	return 0;
}

static struct kprobe apex_kp_do_send_sig = {
	.symbol_name = "do_send_sig_info",
	.pre_handler = apex_kp_do_send_sig_pre,
};

static struct kprobe apex_kp_force_sig = {
	.symbol_name = "force_sig_info",
	.pre_handler = apex_kp_force_sig_pre,
};

static void __init apex_register_signal_probes(void)
{
	int ret;

	ret = register_kprobe(&apex_kp_do_send_sig);
	if (ret)
		pr_err("APEX_SIG: register_kprobe(do_send_sig_info) FAILED ret=%d\n", ret);
	else
		pr_err("APEX_SIG: register_kprobe(do_send_sig_info) OK\n");

	ret = register_kprobe(&apex_kp_force_sig);
	if (ret)
		pr_err("APEX_SIG: register_kprobe(force_sig_info) FAILED ret=%d\n", ret);
	else
		pr_err("APEX_SIG: register_kprobe(force_sig_info) OK\n");
}

/* Forward declarations - these functions are defined later but used
 * by early code (watchdog timer callback, delayed work, etc.) */
static void apex_check_mounts(void);
static void apex_check_tee_status(void);

/* Workqueue for mount checks - kern_path() requires process context,
 * cannot be called from timer softirq context. */
static struct work_struct apex_mount_work;

/* Delayed work for second TEE status check (after ueventd creates /dev nodes) */
static struct delayed_work apex_tee_recheck;
static atomic_t apex_tee_checked = ATOMIC_INIT(0);
static void apex_tee_recheck_fn(struct work_struct *work)
{
	/* Reset the one-shot guard so apex_check_tee_status runs again */
	atomic_set(&apex_tee_checked, 0);
	pr_err("APEX_TEE: === TEE status RE-CHECK (delayed, t~10s) ===\n");
	apex_check_tee_status();
	pr_err("APEX_TEE: === TEE status RE-CHECK done ===\n");
}
static void apex_mount_work_fn(struct work_struct *work)
{
	apex_check_mounts();
}

/* ============================================================
 * Watchdog: dump blocked threads with stack traces
 * Fires every 10 seconds. After 15 seconds starts dumping
 * thread stacks for watched processes.
 * ============================================================ */
static struct timer_list apex_watchdog;
static int apex_dump_count;

static const char * __maybe_unused task_state_str(unsigned long state)
{
	if (state == 0) return "R";  /* Running */
	if (state & TASK_INTERRUPTIBLE) return "S";
	if (state & TASK_UNINTERRUPTIBLE) return "D";
	if (state & TASK_STOPPED) return "T";
	if (state & EXIT_ZOMBIE) return "Z";
	if (state & EXIT_DEAD) return "X";
	return "?";
}

static void __maybe_unused apex_dump_task_stack(struct task_struct *task)
{
	unsigned long entries[16];
	struct stack_trace trace;
	int i;

	trace.nr_entries = 0;
	trace.entries = entries;
	trace.max_entries = 16;
	trace.skip = 0;

	save_stack_trace_tsk(task, &trace);

	for (i = 0; i < trace.nr_entries; i++) {
		pr_err("APEX_WDT:   [%pK] %pS\n",
			(void *)entries[i], (void *)entries[i]);
	}
}

static int __maybe_unused apex_is_watch_target(struct task_struct *task)
{
	struct task_struct *p;

	if (task->flags & PF_KTHREAD)
		return 0;
	if (!strncmp(task->comm, "app_process", 11)) return 1;
	if (!strncmp(task->comm, "zygote", 6)) return 1;
	/* zygote changes comm to "main" after exec */
	if (!strncmp(task->comm, "main", 4) && task->parent) {
		p = task->parent;
		if (!strncmp(p->comm, "init", 4)) return 1;
		if (!strncmp(p->comm, "zygote", 6)) return 1;
		if (!strncmp(p->comm, "main", 4)) return 1;
	}
	if (!strncmp(task->comm, "system_server", 13)) return 1;
	if (!strncmp(task->comm, "surfaceflinger", 14)) return 1;
	if (!strncmp(task->comm, "bootanim", 8)) return 1;
	if (!strncmp(task->comm, "vold", 4)) return 1;
	if (!strncmp(task->comm, "init", 4) && task->pid <= 2) return 1;
	/* Any D-state (TASK_UNINTERRUPTIBLE) userspace process is interesting */
	if (task->state & TASK_UNINTERRUPTIBLE)
		return 1;
	return 0;
}

/* ============================================================
 * Surfaceflinger thread stack dump - ONE-TIME diagnostic
 *
 * When sf>=1 && ba==0 (surfaceflinger running but bootanim never
 * started), dump kernel stack of surfaceflinger and ALL its threads
 * to identify exactly which kernel function it is blocked in
 * (binder_thread_read, futex_wait, io_uring, etc.)
 *
 * Runs EXACTLY ONCE (guarded by atomic flag).
 * ============================================================ */
static atomic_t apex_sf_dumped = ATOMIC_INIT(0);
static atomic_t apex_km_dumped = ATOMIC_INIT(0);

/* Enhanced stack dump for a single task - shows state + stack */
static void apex_dump_task_full(struct task_struct *task)
{
	unsigned long entries[24];
	struct stack_trace trace;
	int i;

	pr_err("APEX_SF: --- pid=%d tgid=%d comm=%s state=%lx flags=%x ---\n",
		task->pid, task->tgid, task->comm,
		task->state, task->flags);

	/* Skip kernel threads - they have no userspace relevance here */
	if (task->flags & PF_KTHREAD) {
		pr_err("APEX_SF:   (kernel thread, skip)\n");
		return;
	}

	trace.nr_entries = 0;
	trace.entries = entries;
	trace.max_entries = 24;
	trace.skip = 0;

	save_stack_trace_tsk(task, &trace);

	if (trace.nr_entries == 0) {
		pr_err("APEX_SF:   (no stack trace available - task may be running)\n");
		return;
	}

	for (i = 0; i < trace.nr_entries; i++) {
		pr_err("APEX_SF:   [%02d] %pS\n", i, (void *)entries[i]);
	}
}

/* Check if process is graphics-related (HWC, allocator, displayfeature, etc.) */
static int apex_is_graphics_process(struct task_struct *task)
{
	/* Graphics HAL services have long comm names truncated to 15 chars.
	 * Match by prefix patterns seen in ramoops logs. */
	if (!strncmp(task->comm, "android.hardwar", 15))
		return 1;  /* android.hardware.* services */
	if (!strncmp(task->comm, "surfaceflinger", 14))
		return 1;
	if (!strncmp(task->comm, "vendor.xiaomi.h", 15))
		return 1;  /* vendor.xiaomi.* services */
	if (!strncmp(task->comm, "vendor.mediatek.", 16))
		return 1;  /* vendor.mediatek.* services - won't match (16 chars) */
	if (!strncmp(task->comm, "vendor.mediatek", 15))
		return 1;  /* vendor.mediatek* services */
	if (!strncmp(task->comm, "gpuservice", 10))
		return 1;
	return 0;
}

static void apex_dump_sf_stacks(void)
{
	struct task_struct *task, *thread;

	/* Guard: only run once */
	if (atomic_xchg(&apex_sf_dumped, 1))
		return;

	pr_err("APEX_SF: === graphics process stack dump (one-shot) ===\n");
	pr_err("APEX_SF: jiffies=%lu t=%ds\n",
		jiffies, (int)(jiffies_to_msecs(jiffies) / 1000));

	rcu_read_lock();

	/* Phase 1: dump surfaceflinger (main suspect) */
	for_each_process(task) {
		if (strncmp(task->comm, "surfaceflinger", 14))
			continue;

		pr_err("APEX_SF: >>> surfaceflinger main process pid=%d state=%lx <<<\n",
			task->pid, task->state);
		apex_dump_task_full(task);

		for_each_thread(task, thread) {
			if (thread == task)
				continue;
			pr_err("APEX_SF: >>> thread pid=%d comm=%s <<<\n",
				thread->pid, thread->comm);
			apex_dump_task_full(thread);
		}
	}

	/* Phase 2: dump ALL graphics-related HAL services
	 * (HWC composer, allocator, displayfeature, gpuservice, etc.)
	 * These are the binder endpoints surfaceflinger talks to.
	 * If surfaceflinger is blocked in binder_ioctl_write_read,
	 * the blocking endpoint is likely one of these. */
	for_each_process(task) {
		/* Skip surfaceflinger - already dumped above */
		if (!strncmp(task->comm, "surfaceflinger", 14))
			continue;

		if (!apex_is_graphics_process(task))
			continue;

		pr_err("APEX_SF: >>> graphics HAL pid=%d comm=%s state=%lx <<<\n",
			task->pid, task->comm, task->state);
		apex_dump_task_full(task);

		/* Dump all threads in this HAL service */
		for_each_thread(task, thread) {
			if (thread == task)
				continue;
			pr_err("APEX_SF: >>> HAL thread pid=%d comm=%s <<<\n",
				thread->pid, thread->comm);
			apex_dump_task_full(thread);
		}
	}

	rcu_read_unlock();

	pr_err("APEX_SF: === stack dump done ===\n");
}

/* ============================================================
 * Keymaster HAL stack dump
 *
 * Dumps kernel stacks for keymaster HAL (beanpod) and keystore2
 * processes. This helps diagnose why keymaster HAL never calls
 * send_keymaster_command() — it may be blocked in binder ioctl,
 * open(), read(), or spinning in userspace.
 *
 * Called from watchdog at t~10s (before system_server crash at t~14s).
 * ============================================================ */
static void apex_dump_keymaster_stacks(void)
{
	struct task_struct *task, *thread;
	int i;
	int km_found = 0;

	/* Guard: only run once */
	if (atomic_xchg(&apex_km_dumped, 1))
		return;

	pr_err("APEX_KM: === keymaster HAL stack dump (by pid) ===\n");
	pr_err("APEX_KM: t=%ds tracked_km_pids=%d\n",
		(int)(jiffies_to_msecs(jiffies) / 1000), apex_km_pid_count);

	/* Print all tracked keymaster pids */
	for (i = 0; i < apex_km_pid_count && i < APEX_KM_PID_MAX; i++)
		pr_err("APEX_KM: tracked pid[%d]=%d\n",
			i, atomic_read(&apex_km_pids[i]));

	rcu_read_lock();

	for_each_process(task) {
		int dump = 0;

		/* Match by tracked keymaster pid (precise) */
		if (apex_is_km_pid(task->pid))
			dump = 1;

		/* Also match keystore2 and teei_daemon by comm */
		if (!strncmp(task->comm, "keystore2", 9))
			dump = 1;
		if (!strncmp(task->comm, "teei_daemon", 11))
			dump = 1;

		if (!dump)
			continue;

		if (apex_is_km_pid(task->pid))
			km_found = 1;

		pr_err("APEX_KM: >>> %s pid=%d state=%lx flags=%x%s <<<\n",
			task->comm, task->pid, task->state, task->flags,
			apex_is_km_pid(task->pid) ? " [KEYMASTER]" : "");
		apex_dump_task_full(task);

		for_each_thread(task, thread) {
			if (thread == task)
				continue;
			pr_err("APEX_KM: >>> thread pid=%d comm=%s state=%lx <<<\n",
				thread->pid, thread->comm, thread->state);
			apex_dump_task_full(thread);
		}
	}

	rcu_read_unlock();

	if (!km_found) {
		pr_err("APEX_KM: *** WARNING: no tracked keymaster HAL process found! ***\n");
		pr_err("APEX_KM: *** keymaster HAL may have EXITED before this dump. ***\n");
		pr_err("APEX_KM: *** Check APEX_KM: exit logs above for crash/exit info. ***\n");
	}

	pr_err("APEX_KM: === stack dump done ===\n");
}

static void apex_watchdog_fn(struct timer_list *t)
{
	struct task_struct *task;
	int sf = 0, zy = 0, ba = 0, ss = 0, vold = 0;

	rcu_read_lock();
	for_each_process(task) {
		if (strncmp(task->comm, "surfaceflinger", 14) == 0) sf++;
		else if (strncmp(task->comm, "main", 4) == 0 &&
			 task->parent &&
			 strncmp(task->parent->comm, "zygote", 6) == 0) zy++;
		else if (strncmp(task->comm, "bootanim", 8) == 0) ba++;
		else if (strncmp(task->comm, "system_server", 13) == 0) ss++;
		else if (strncmp(task->comm, "vold", 4) == 0) vold++;
	}
	rcu_read_unlock();

	/* Single-line status summary - minimal log footprint */
	pr_err("APEX_WDT: t=%ds sf=%d zy=%d ba=%d ss=%d vold=%d\n",
		(int)(jiffies_to_msecs(jiffies) / 1000), sf, zy, ba, ss, vold);

	/* Only do mount check ONCE at 10s, not every 5s */
	if (jiffies_to_msecs(jiffies) >= 10000 && apex_dump_count == 0) {
		apex_dump_count = 1;
		schedule_work(&apex_mount_work);
	}

	/* Dump keymaster HAL stacks ONCE at t>=9.5s
	 * TEE completes init at t~9.4s, keystore2 calls earlyBootEnded
	 * at t~9.4s and gets error -68. keymaster HAL (pid=597) starts
	 * at t~9.25s. Dump at t=9.5s to capture keymaster HAL state
	 * immediately after TEE init completes. */
	if (jiffies_to_msecs(jiffies) >= 9500)
		apex_dump_keymaster_stacks();

	/* Surfaceflinger stuck: sf alive but bootanim never started.
	 * Dump stacks ONCE to identify blocking point. */
	if (sf >= 1 && ba == 0)
		apex_dump_sf_stacks();

	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
}

/* ============================================================
 * vbmeta partition dump - verify block device read correctness
 * Reads the AVB vbmeta header and verifies the magic + hash_size.
 * ============================================================ */
static void __maybe_unused apex_dump_vbmeta(void)
{
	struct block_device *bdev;
	struct gendisk *disk;
	struct hd_struct *part;
	struct buffer_head *bh = NULL;
	sector_t sector;
	char *data;
	char local_data[512];
	u64 hash_size;
	int i;

	/* Try to find vbmeta partition via get_part */
	part = get_part("vbmeta");
	if (!part) {
		pr_err("APEX_VBMETA: get_part('vbmeta') returned NULL\n");
		part = get_part("vbmeta_a");
		if (!part) {
			pr_err("APEX_VBMETA: get_part('vbmeta_a') also NULL\n");
			return;
		}
		pr_err("APEX_VBMETA: found 'vbmeta_a' instead\n");
	}

	pr_err("APEX_VBMETA: partition start_sect=%llu nr_sects=%llu\n",
		(unsigned long long)part->start_sect,
		(unsigned long long)part->nr_sects);

	/* Get the whole disk block_device */
	disk = dev_to_disk(part_to_dev(part)->parent);
	if (!disk) {
		pr_err("APEX_VBMETA: cannot get disk\n");
		return;
	}

	/* blkdev_get_by_dev properly initializes the bdev
	 * (bdget alone is not enough) */
	bdev = blkdev_get_by_dev(disk_devt(disk), FMODE_READ, NULL);
	if (IS_ERR_OR_NULL(bdev)) {
		pr_err("APEX_VBMETA: blkdev_get_by_dev failed: %ld\n",
			PTR_ERR(bdev));
		return;
	}

	/* Read first 512 bytes of vbmeta partition */
	sector = part->start_sect;

	/* Method 1: try __bread first */
	bh = __bread(bdev, sector, 512);
	if (bh) {
		data = (char *)bh->b_data;
		pr_err("APEX_VBMETA: __bread succeeded, dumping data:\n");
	} else {
		/* Method 2: read via page cache directly */
		struct page *page;
		char *kaddr;
		pgoff_t index;

		pr_err("APEX_VBMETA: __bread failed for sector %llu, trying page cache\n",
			(unsigned long long)sector);

		index = sector >> (PAGE_SHIFT - SECTOR_SHIFT);
		page = read_mapping_page(bdev->bd_inode->i_mapping, index,
					 NULL);
		if (IS_ERR_OR_NULL(page)) {
			pr_err("APEX_VBMETA: read_mapping_page failed: %ld\n",
				PTR_ERR(page));
			blkdev_put(bdev, FMODE_READ);
			return;
		}

		kaddr = kmap(page);
		memcpy(local_data,
		       kaddr + ((sector &
		       ((1 << (PAGE_SHIFT - SECTOR_SHIFT)) - 1)) * 512),
		       512);
		kunmap(page);
		put_page(page);
		data = local_data;
		pr_err("APEX_VBMETA: page cache read succeeded, dumping data:\n");
	}

	/* Print hexdump of first 64 bytes (16 bytes per line) */
	pr_err("APEX_VBMETA: first 64 bytes of vbmeta:\n");
	for (i = 0; i < 64; i += 16) {
		pr_err("APEX_VBMETA: %03x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			i,
			(unsigned char)data[i], (unsigned char)data[i+1],
			(unsigned char)data[i+2], (unsigned char)data[i+3],
			(unsigned char)data[i+4], (unsigned char)data[i+5],
			(unsigned char)data[i+6], (unsigned char)data[i+7],
			(unsigned char)data[i+8], (unsigned char)data[i+9],
			(unsigned char)data[i+10], (unsigned char)data[i+11],
			(unsigned char)data[i+12], (unsigned char)data[i+13],
			(unsigned char)data[i+14], (unsigned char)data[i+15]);
	}

	/* Check AVB magic "AVB0" at offset 0-3 */
	if (data[0] == 'A' && data[1] == 'V' &&
	    data[2] == 'B' && data[3] == '0') {
		/* Read hash_size from offset 40-47 (big-endian u64).
		 * NOTE: This is offset 40-47, NOT offset 8-11!
		 * The AVB vbmeta header layout:
		 *   0-3:   magic "AVB0"
		 *   4-7:   major_version
		 *   8-11:  minor_version
		 *   12-19: authentication_data_block_size
		 *   20-27: auxiliary_data_block_size
		 *   28-31: algorithm_type
		 *   32-39: hash_offset
		 *   40-47: hash_size  <-- THIS IS WHAT WE WANT
		 */
		hash_size = ((u64)(unsigned char)data[40] << 56) |
			    ((u64)(unsigned char)data[41] << 48) |
			    ((u64)(unsigned char)data[42] << 40) |
			    ((u64)(unsigned char)data[43] << 32) |
			    ((u64)(unsigned char)data[44] << 24) |
			    ((u64)(unsigned char)data[45] << 16) |
			    ((u64)(unsigned char)data[46] << 8)  |
			    ((u64)(unsigned char)data[47]);
		pr_err("APEX_VBMETA: AVB magic OK! hash_size=%llu\n",
			(unsigned long long)hash_size);
	} else {
		pr_err("APEX_VBMETA: AVB magic NOT found! first 4 bytes: %02x %02x %02x %02x\n",
			(unsigned char)data[0], (unsigned char)data[1],
			(unsigned char)data[2], (unsigned char)data[3]);
	}

	if (bh)
		brelse(bh);
	blkdev_put(bdev, FMODE_READ);
}

/* ============================================================
 * Partition listing - dump all partitions on the main block device
 * ============================================================ */
static void __maybe_unused apex_dump_partitions(void)
{
	dev_t devt;
	int partno;
	struct gendisk *disk;
	struct hd_struct *part;
	struct disk_part_iter piter;
	unsigned int boot_type;

	boot_type = get_boot_type();
	if (boot_type == BOOTDEV_UFS)
		devt = blk_lookup_devt("sdc", 0);
	else
		devt = blk_lookup_devt("mmcblk0", 0);

	disk = get_gendisk(devt, &partno);
	if (!disk || get_capacity(disk) == 0) {
		pr_err("APEX_PART: cannot get disk (boot_type=%u)\n", boot_type);
		return;
	}

	pr_err("APEX_PART: disk=%s boot_type=%u capacity=%llu sectors\n",
		disk->disk_name, boot_type,
		(unsigned long long)get_capacity(disk));

	disk_part_iter_init(&piter, disk, 0);
	while ((part = disk_part_iter_next(&piter))) {
		const char *name = "(none)";

		if (part->info && part->info->volname[0])
			name = part->info->volname;
		pr_err("APEX_PART:  part%d start=%llu nr_sects=%llu volname='%s'\n",
			part->partno,
			(unsigned long long)part->start_sect,
			(unsigned long long)part->nr_sects,
			name);
	}
	disk_part_iter_exit(&piter);
}

/* ============================================================
 * Metadata partition check - read first sector to look for checkpoint
 * magic bytes that vold expects.
 * ============================================================ */
static void __maybe_unused apex_check_metadata_part(void)
{
	struct hd_struct *part;
	struct block_device *bdev;
	struct gendisk *disk;
	struct buffer_head *bh = NULL;
	struct page *page;
	sector_t sector;
	char *data;
	char local_data[512];
	pgoff_t index;
	int i;

	part = get_part("metadata");
	if (!part) {
		pr_err("APEX_META: get_part('metadata') returned NULL\n");
		return;
	}

	pr_err("APEX_META: partition found start_sect=%llu nr_sects=%llu\n",
		(unsigned long long)part->start_sect,
		(unsigned long long)part->nr_sects);

	disk = dev_to_disk(part_to_dev(part)->parent);
	if (!disk) {
		pr_err("APEX_META: cannot get disk\n");
		return;
	}

	bdev = blkdev_get_by_dev(disk_devt(disk), FMODE_READ, NULL);
	if (IS_ERR_OR_NULL(bdev)) {
		pr_err("APEX_META: blkdev_get_by_dev failed: %ld\n",
			PTR_ERR(bdev));
		return;
	}

	sector = part->start_sect;

	/* Try __bread first */
	bh = __bread(bdev, sector, 512);
	if (bh) {
		data = (char *)bh->b_data;
		pr_err("APEX_META: __bread succeeded\n");
	} else {
		/* Fallback: page cache read */
		pr_err("APEX_META: __bread failed, trying page cache\n");
		index = sector >> (PAGE_SHIFT - SECTOR_SHIFT);
		page = read_mapping_page(bdev->bd_inode->i_mapping, index,
					 NULL);
		if (IS_ERR_OR_NULL(page)) {
			pr_err("APEX_META: read_mapping_page failed: %ld\n",
				PTR_ERR(page));
			blkdev_put(bdev, FMODE_READ);
			return;
		}
		memcpy(local_data,
		       kmap(page) + ((sector &
		       ((1 << (PAGE_SHIFT - SECTOR_SHIFT)) - 1)) * 512),
		       512);
		kunmap(page);
		put_page(page);
		data = local_data;
		pr_err("APEX_META: page cache read succeeded\n");
	}

	/* Hexdump first 64 bytes */
	pr_err("APEX_META: first 64 bytes:\n");
	for (i = 0; i < 64; i += 16) {
		pr_err("APEX_META: %03x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			i,
			(unsigned char)data[i], (unsigned char)data[i+1],
			(unsigned char)data[i+2], (unsigned char)data[i+3],
			(unsigned char)data[i+4], (unsigned char)data[i+5],
			(unsigned char)data[i+6], (unsigned char)data[i+7],
			(unsigned char)data[i+8], (unsigned char)data[i+9],
			(unsigned char)data[i+10], (unsigned char)data[i+11],
			(unsigned char)data[i+12], (unsigned char)data[i+13],
			(unsigned char)data[i+14], (unsigned char)data[i+15]);
	}

	/* Check for ext4 magic (0xEF53 at offset 0x438) and
	 * f2fs magic (0xF2F52010 at offset 0x0) */
	if (data[0] == (char)0xF2 && data[1] == (char)0xF5 &&
	    data[2] == 0x20 && data[3] == 0x10) {
		pr_err("APEX_META: f2fs magic detected at offset 0\n");
	}

	if (bh)
		brelse(bh);
	blkdev_put(bdev, FMODE_READ);
}

/* ============================================================
 * Mount point check - verify if key paths are mounted
 * Called from watchdog timer (after init has had time to mount)
 * ============================================================ */
static void apex_check_mount(const char *path)
{
	struct path p;
	int err;
	const char *fs_type = "(unknown)";
	const char *s_id = "(unknown)";

	err = kern_path(path, LOOKUP_FOLLOW, &p);
	if (err) {
		pr_err("APEX_MOUNT: '%s': NOT FOUND (err=%d)\n", path, err);
		return;
	}

	/* If dentry is the root of its mount, this is a mount point */
	if (p.mnt->mnt_root == p.dentry) {
		if (p.mnt->mnt_sb->s_type && p.mnt->mnt_sb->s_type->name)
			fs_type = p.mnt->mnt_sb->s_type->name;
		if (p.mnt->mnt_sb->s_id[0])
			s_id = p.mnt->mnt_sb->s_id;
		pr_err("APEX_MOUNT: '%s': MOUNTED fs=%s dev=%s\n",
			path, fs_type, s_id);
	} else {
		pr_err("APEX_MOUNT: '%s': exists but NOT a mount point\n",
			path);
	}

	path_put(&p);
}

static void apex_check_mounts(void)
{
	struct path p;
	int err;

	pr_err("APEX_MOUNT: check at t=%ds\n",
		(int)(jiffies_to_msecs(jiffies) / 1000));

	/* Only check the most critical paths for bootanim issue */
	apex_check_mount("/dev/binder");
	apex_check_mount("/dev/hwbinder");
	apex_check_mount("/dev/vndbinder");
	apex_check_mount("/dev/fb0");
	apex_check_mount("/dev/dri/card0");

	/* Critical: /metadata partition - vold checkpoint needs this */
	apex_check_mount("/metadata");

	/* Critical: /data partition - fscrypt target */
	apex_check_mount("/data");

	/* Check bootanimation binary */
	err = kern_path("/system/bin/bootanimation", 0, &p);
	if (err)
		pr_err("APEX_MOUNT: bootanimation: NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_MOUNT: bootanimation: EXISTS\n");
		path_put(&p);
	}

	/* Check vold checkpoint file - "No magic" error source */
	err = kern_path("/metadata/vold", 0, &p);
	if (err)
		pr_err("APEX_MOUNT: /metadata/vold: NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_MOUNT: /metadata/vold: EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/metadata/vold/checkpoint", 0, &p);
	if (err)
		pr_err("APEX_MOUNT: /metadata/vold/checkpoint: NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_MOUNT: /metadata/vold/checkpoint: EXISTS\n");
		path_put(&p);
	}
}

/* ============================================================
 * Kernel command line dump
 * ============================================================ */
static void apex_dump_cmdline(void)
{
	char *p;

	pr_err("APEX_CMDLINE: %s\n", saved_command_line);

	/* Search for androidboot */
	p = strstr(saved_command_line, "androidboot");
	if (p) {
		char tmp[256];
		char *end = strchr(p, ' ');
		int len = end ? (int)(end - p) : (int)strlen(p);

		if (len > 255)
			len = 255;
		memcpy(tmp, p, len);
		tmp[len] = 0;
		pr_err("APEX_CMDLINE: androidboot: %s\n", tmp);
	}

	/* Search for slot_suffix */
	p = strstr(saved_command_line, "slot_suffix");
	if (p) {
		char tmp[256];
		char *end = strchr(p, ' ');
		int len = end ? (int)(end - p) : (int)strlen(p);

		if (len > 255)
			len = 255;
		memcpy(tmp, p, len);
		tmp[len] = 0;
		pr_err("APEX_CMDLINE: slot_suffix: %s\n", tmp);
	}
}

/* ============================================================
 * fscrypt kprobe tracing - diagnose vold crypto failures
 * ============================================================ */

/* fscrypt_ioctl is the main entry point for all fscrypt ioctls.
 * Signature: int fscrypt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
 * arm64 regs: x0=filp, x1=cmd, x2=arg
 */
static int apex_kp_fscrypt_ioctl_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int cmd = (unsigned int)regs->regs[1];

	pr_err("APEX_FSCRYPT: fscrypt_ioctl ENTER cmd=0x%08x\n", cmd);
	return 0;
}

static struct kprobe apex_kp_fscrypt_ioctl = {
	.symbol_name = "fscrypt_ioctl",
	.pre_handler = apex_kp_fscrypt_ioctl_pre,
};

/* fscrypt_ioctl_add_key - installs an fscrypt master key
 * This is what vold calls to install the user key.
 * If this fails, ro.crypto.state won't be set.
 */
static int apex_kp_add_key_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_err("APEX_FSCRYPT: fscrypt_ioctl_add_key ENTER\n");
	return 0;
}

static int apex_kp_add_key_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	int retval = (int)regs_return_value(regs);
	pr_err("APEX_FSCRYPT: fscrypt_ioctl_add_key RETURN retval=%d\n",
	       retval);
	return 0;
}

static struct kprobe apex_kp_add_key = {
	.symbol_name = "fscrypt_ioctl_add_key",
	.pre_handler = apex_kp_add_key_pre,
};

static struct kretprobe apex_krp_add_key = {
	.handler = apex_kp_add_key_ret,
	.kp.symbol_name = "fscrypt_ioctl_add_key",
};

/* fscrypt_add_key - lower-level key addition function */
static int apex_kp_fscrypt_add_key_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_err("APEX_FSCRYPT: fscrypt_add_key ENTER\n");
	return 0;
}

static struct kprobe apex_kp_fscrypt_add_key = {
	.symbol_name = "fscrypt_add_key",
	.pre_handler = apex_kp_fscrypt_add_key_pre,
};

/* fscrypt_setup_encryption_key - sets up key for an encrypted inode */
static int apex_kp_setup_key_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_err("APEX_FSCRYPT: fscrypt_setup_encryption_key ENTER\n");
	return 0;
}

static struct kprobe apex_kp_setup_key = {
	.symbol_name = "fscrypt_setup_encryption_key",
	.pre_handler = apex_kp_setup_key_pre,
};

/* fscrypt_get_encryption_info - retrieves encryption info for inode
 * NOTE: This function is called extremely frequently (thousands of times).
 * Only log the FIRST call and errors to avoid flooding the log buffer.
 */
static atomic_t apex_get_enc_info_count = ATOMIC_INIT(0);

static int apex_kp_get_enc_info_pre(struct kprobe *p, struct pt_regs *regs)
{
	int count = atomic_inc_return(&apex_get_enc_info_count);
	if (count <= 3)
		pr_err("APEX_FSCRYPT: fscrypt_get_encryption_info ENTER (call #%d)\n",
		       count);
	return 0;
}

static int apex_kp_get_enc_info_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	int retval = (int)regs_return_value(regs);
	int count = atomic_read(&apex_get_enc_info_count);
	if (count <= 3 || retval < 0)
		pr_err("APEX_FSCRYPT: fscrypt_get_encryption_info RETURN retval=%d (call #%d)\n",
		       retval, count);
	return 0;
}

static struct kprobe apex_kp_get_enc_info = {
	.symbol_name = "fscrypt_get_encryption_info",
	.pre_handler = apex_kp_get_enc_info_pre,
};

static struct kretprobe apex_krp_get_enc_info = {
	.handler = apex_kp_get_enc_info_ret,
	.kp.symbol_name = "fscrypt_get_encryption_info",
};

/* fscrypt_prepare_lookup - prepare lookup with encryption
 * NOTE: Also called very frequently, rate-limit to first 3 calls.
 */
static atomic_t apex_prep_lookup_count = ATOMIC_INIT(0);

static int apex_kp_prep_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
	int count = atomic_inc_return(&apex_prep_lookup_count);
	if (count <= 3)
		pr_err("APEX_FSCRYPT: fscrypt_prepare_lookup ENTER (call #%d)\n",
		       count);
	return 0;
}

static struct kprobe apex_kp_prep_lookup = {
	.symbol_name = "fscrypt_prepare_lookup",
	.pre_handler = apex_kp_prep_lookup_pre,
};

/* fscrypt_ioctl_set_policy - sets encryption policy on directory */
static int apex_kp_set_policy_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_err("APEX_FSCRYPT: fscrypt_ioctl_set_policy ENTER\n");
	return 0;
}

static struct kprobe apex_kp_set_policy = {
	.symbol_name = "fscrypt_ioctl_set_policy",
	.pre_handler = apex_kp_set_policy_pre,
};

/* Register all kprobes, print error if symbol not found */
static void __init apex_register_fscrypt_probes(void)
{
	int ret;

#define REGISTER_KPROBE(kp) \
	do { \
		ret = register_kprobe(kp); \
		if (ret) \
			pr_err("APEX_FSCRYPT: register_kprobe(%s) FAILED ret=%d\n", \
			       (kp)->symbol_name, ret); \
		else \
			pr_err("APEX_FSCRYPT: register_kprobe(%s) OK\n", \
			       (kp)->symbol_name); \
	} while (0)

#define REGISTER_KRETPROBE(krp) \
	do { \
		ret = register_kretprobe(krp); \
		if (ret) \
			pr_err("APEX_FSCRYPT: register_kretprobe(%s) FAILED ret=%d\n", \
			       (krp)->kp.symbol_name, ret); \
		else \
			pr_err("APEX_FSCRYPT: register_kretprobe(%s) OK\n", \
			       (krp)->kp.symbol_name); \
	} while (0)

	REGISTER_KPROBE(&apex_kp_fscrypt_ioctl);
	REGISTER_KPROBE(&apex_kp_add_key);
	REGISTER_KRETPROBE(&apex_krp_add_key);
	REGISTER_KPROBE(&apex_kp_fscrypt_add_key);
	REGISTER_KPROBE(&apex_kp_setup_key);
	REGISTER_KPROBE(&apex_kp_get_enc_info);
	REGISTER_KRETPROBE(&apex_krp_get_enc_info);
	REGISTER_KPROBE(&apex_kp_prep_lookup);
	REGISTER_KPROBE(&apex_kp_set_policy);

#undef REGISTER_KPROBE
#undef REGISTER_KRETPROBE
}

/* ============================================================
 * MicroTrust TEE driver status check - ONE-TIME diagnostic
 *
 * Based on source analysis of drivers/misc/mediatek/teei/400/:
 *   - teei_client_main.c: module_init + platform_driver,
 *     compatible="microtrust,utos"
 *   - teei_log_thread: kernel thread started in teei_probe()
 *   - TEEI_CONFIG_IOCTL_INIT_TEEI: ioctl that triggers real TEE OS load
 *   - SMC 0xB2000007: routed by ATF to MicroTrust Soter
 *
 * Official 4.14.186 kernel shows teei_log_thread + [TZ_LOG] at t=11.7s.
 * Self-compiled 4.14.336 has NO TEE logs - this check identifies why.
 *
 * All checks run EXACTLY ONCE (guarded by atomic flag).
 * ============================================================ */

static void apex_check_tee_status(void)
{
	struct task_struct *task;
	struct path p;
	int err;

	/* Guard: only run once per call (caller manages the atomic) */
	pr_err("APEX_TEE: === MicroTrust TEE status check ===\n");

	/* 1. Compile-time Kconfig macros - verified against defconfig */
#ifdef CONFIG_MICROTRUST_TEE_SUPPORT
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TEE_SUPPORT=y (compiled in)\n");
#else
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TEE_SUPPORT NOT set (driver NOT compiled!)\n");
#endif

#ifdef CONFIG_MICROTRUST_TEE_VERSION
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TEE_VERSION=\"%s\"\n",
	       CONFIG_MICROTRUST_TEE_VERSION);
#else
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TEE_VERSION NOT set\n");
#endif

#ifdef CONFIG_MICROTRUST_TZ_DRIVER
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TZ_DRIVER=y\n");
#else
	pr_err("APEX_TEE: CONFIG_MICROTRUST_TZ_DRIVER NOT set\n");
#endif

#ifdef CONFIG_MICROTRUST_KEYMASTER_DRIVER
	pr_err("APEX_TEE: CONFIG_MICROTRUST_KEYMASTER_DRIVER=y\n");
#else
	pr_err("APEX_TEE: CONFIG_MICROTRUST_KEYMASTER_DRIVER NOT set\n");
#endif

	/* 2. Device tree node - teei_driver matches "microtrust,utos" */
	{
		struct device_node *np;

		np = of_find_compatible_node(NULL, NULL, "microtrust,utos");
		if (np) {
			pr_err("APEX_TEE: DT node 'microtrust,utos' FOUND name=%s\n",
			       np->name ? np->name : "(null)");
			of_node_put(np);
		} else {
			pr_err("APEX_TEE: DT node 'microtrust,utos' NOT FOUND\n");
		}
	}

	/* 3. Kernel symbols - verify teei driver actually linked */
	{
		unsigned long addr;

		addr = kallsyms_lookup_name("teei_probe");
		pr_err("APEX_TEE: kallsyms teei_probe=%pS (addr=%lx)\n",
		       (void *)addr, addr);

		addr = kallsyms_lookup_name("teei_log_thread");
		pr_err("APEX_TEE: kallsyms teei_log_thread=%pS (addr=%lx)\n",
		       (void *)addr, addr);

		addr = kallsyms_lookup_name("teei_init");
		pr_err("APEX_TEE: kallsyms teei_init=%pS (addr=%lx)\n",
		       (void *)addr, addr);
	}

	/* 4. Device nodes created by teei driver */
	err = kern_path("/dev/tz", 0, &p);
	if (err)
		pr_err("APEX_TEE: /dev/tz NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_TEE: /dev/tz EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/dev/teei_config", 0, &p);
	if (err)
		pr_err("APEX_TEE: /dev/teei_config NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_TEE: /dev/teei_config EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/dev/teei_client", 0, &p);
	if (err)
		pr_err("APEX_TEE: /dev/teei_client NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_TEE: /dev/teei_client EXISTS\n");
		path_put(&p);
	}

	/* 5. Kernel threads - teei_log_thread should exist if probe ran */
	rcu_read_lock();
	for_each_process(task) {
		if (!strncmp(task->comm, "teei_log_thread", 15)) {
			pr_err("APEX_TEE: thread 'teei_log_thread' FOUND pid=%d state=%ld\n",
			       task->pid, task->state);
		}
		if (!strncmp(task->comm, "teei_daemon", 11)) {
			pr_err("APEX_TEE: thread 'teei_daemon' FOUND pid=%d state=%ld\n",
			       task->pid, task->state);
		}
		if (!strncmp(task->comm, "teei", 4)) {
			pr_err("APEX_TEE: thread '%s' FOUND pid=%d state=%ld\n",
			       task->comm, task->pid, task->state);
		}
	}
	rcu_read_unlock();

	pr_err("APEX_TEE: === TEE status check done ===\n");
}

/* ============================================================
 * Display driver status check - ONE-TIME diagnostic
 *
 * Checks /dev/fb0, /dev/dri/card0, /dev/dri/renderD128
 * Dumps LCM/DRM related kernel symbols
 * ============================================================ */
static atomic_t apex_display_checked = ATOMIC_INIT(0);

static void apex_check_display_status(void)
{
	struct path p;
	int err;
	unsigned long addr;

	if (atomic_xchg(&apex_display_checked, 1))
		return;

	pr_err("APEX_DISP: === display driver status check (one-shot) ===\n");

	/* Device nodes */
	err = kern_path("/dev/fb0", 0, &p);
	if (err)
		pr_err("APEX_DISP: /dev/fb0 NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_DISP: /dev/fb0 EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/dev/dri/card0", 0, &p);
	if (err)
		pr_err("APEX_DISP: /dev/dri/card0 NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_DISP: /dev/dri/card0 EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/dev/dri/renderD128", 0, &p);
	if (err)
		pr_err("APEX_DISP: /dev/dri/renderD128 NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_DISP: /dev/dri/renderD128 EXISTS\n");
		path_put(&p);
	}

	err = kern_path("/dev/graphics/fb0", 0, &p);
	if (err)
		pr_err("APEX_DISP: /dev/graphics/fb0 NOT FOUND (err=%d)\n", err);
	else {
		pr_err("APEX_DISP: /dev/graphics/fb0 EXISTS\n");
		path_put(&p);
	}

	/* DRM/MTK display kernel symbols */
	addr = kallsyms_lookup_name("mtk_drm_init");
	pr_err("APEX_DISP: kallsyms mtk_drm_init=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	addr = kallsyms_lookup_name("mtk_drm_probe");
	pr_err("APEX_DISP: kallsyms mtk_drm_probe=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	addr = kallsyms_lookup_name("lcm_fps_ctx_init");
	pr_err("APEX_DISP: kallsyms lcm_fps_ctx_init=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	addr = kallsyms_lookup_name("mtk_fb_init");
	pr_err("APEX_DISP: kallsyms mtk_fb_init=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	addr = kallsyms_lookup_name("disp_init_hal");
	pr_err("APEX_DISP: kallsyms disp_init_hal=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	/* DRM device class - check if DRM subsystem registered */
	addr = kallsyms_lookup_name("drm_class");
	pr_err("APEX_DISP: kallsyms drm_class=%pS (addr=%lx)\n",
	       (void *)addr, addr);

	pr_err("APEX_DISP: === display status check done ===\n");
}

/* ============================================================
 * Init
 * ============================================================ */
static int __init apex_debug_init(void)
{
	pr_err("APEX: apex_debug loaded. kernel=%s\n", utsname()->release);

	/* Dump kernel command line only - minimal startup info */
	apex_dump_cmdline();

	/* One-shot MicroTrust TEE driver status check */
	apex_check_tee_status();

	/* Schedule delayed TEE re-check at t~10s (after ueventd creates /dev nodes) */
	INIT_DELAYED_WORK(&apex_tee_recheck, apex_tee_recheck_fn);
	schedule_delayed_work(&apex_tee_recheck, 10 * HZ);

	/* One-shot display driver status check */
	apex_check_display_status();

	/* Initialize workqueue for mount checks from timer context */
	INIT_WORK(&apex_mount_work, apex_mount_work_fn);

	/* Register fscrypt kprobes for crypto failure diagnosis */
	apex_register_fscrypt_probes();

	/* Register signal delivery kprobes to capture process crash signals */
	apex_register_signal_probes();

	/* Start watchdog - first fire at 10s, then every 10s */
	timer_setup(&apex_watchdog, apex_watchdog_fn, 0);
	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
	return 0;
}
late_initcall(apex_debug_init);

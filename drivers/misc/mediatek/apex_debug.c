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
	/* [APEX] Critical for boot chain */
	"bpfloader",
	"/system/bin/bpfloader",
	"bootctrl",
	"android.hardware.boot",
	"boot.control",
	"/vendor/bin/hw/android.hardware.boot",
	"linkerconfig",
	"/system/bin/linkerconfig",
	"secilc",
	"/system/bin/secilc",
	"apexd",
	"/system/bin/apexd",
	"init",
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

/* ============================================================
 * Hook 1: exec tracking
 * ============================================================ */
void apex_exec_hook(const char *filename)
{
	if (!filename)
		return;

	/* Always log watched binaries */
	if (apex_watch_exec(filename)) {
		pr_err("APEX_EXEC: pid=%d comm=%s exec='%s'\n",
			current->pid, current->comm, filename);
		return;
	}

	/* Also log ALL exec from pid 1 (init) to trace action chain */
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

/* ============================================================
 * Hook 2: exit tracking
 * ============================================================ */
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
	    strncmp(t->comm, "netd", 4) &&
	    strncmp(t->comm, "bpfloader", 9) &&
	    strncmp(t->comm, "bootctrl", 8) &&
	    strncmp(t->comm, "secilc", 6) &&
	    strncmp(t->comm, "apexd", 5) &&
	    strncmp(t->comm, "linkerconfig", 12) &&
	    strncmp(t->comm, "keystore2", 9))
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

/* ============================================================
 * Watchdog: dump blocked threads with stack traces
 * ============================================================ */
static struct timer_list apex_watchdog;
static int apex_dump_count;

static const char *task_state_str(unsigned long state)
{
	if (state == 0) return "R";  /* Running */
	if (state & TASK_INTERRUPTIBLE) return "S";
	if (state & TASK_UNINTERRUPTIBLE) return "D";
	if (state & TASK_STOPPED) return "T";
	if (state & EXIT_ZOMBIE) return "Z";
	if (state & EXIT_DEAD) return "X";
	return "?";
}

static void apex_dump_task_stack(struct task_struct *task)
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

static int apex_is_watch_target(struct task_struct *task)
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
	if (!strncmp(task->comm, "init", 4) && task->pid <= 2) return 1;
	/* Any D-state userspace process is interesting */
	if (task->state & TASK_UNINTERRUPTIBLE)
		return 1;
	return 0;
}

static void apex_watchdog_fn(struct timer_list *t)
{
	struct task_struct *task, *thread;
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

	pr_err("APEX_WDT: [%.1fs] sf=%d zygote_kids=%d bootanim=%d sys_srv=%d\n",
		(float)jiffies_to_msecs(jiffies) / 1000, sf, zy, ba, ss);

	/* After 15s, dump detailed thread status for watched processes */
	if (jiffies_to_msecs(jiffies) > 15000 || apex_dump_count > 0) {
		apex_dump_count++;
		pr_err("APEX_WDT: === Thread dump #%d ===\n", apex_dump_count);
		rcu_read_lock();
		for_each_process(task) {
			int nthreads = 0;
			struct task_struct *t;

			if (!apex_is_watch_target(task))
				continue;

			/* Count threads */
			for_each_thread(task, t)
				nthreads++;

			pr_err("APEX_WDT: --- pid=%d comm=%-16s threads=%d state=%s ---\n",
				task->pid, task->comm, nthreads,
				task_state_str(task->state));

			/* Dump each thread of the process */
			for_each_thread(task, thread) {
				unsigned long wchan;
				char wchan_buf[128];

				wchan = get_wchan(thread);
				wchan_buf[0] = 0;
				if (wchan)
					snprintf(wchan_buf, sizeof(wchan_buf),
						"%pS", (void *)wchan);

				pr_err("APEX_WDT: pid=%d tgid=%d comm=%-16s state=%s wchan=%s\n",
					thread->pid, thread->tgid, thread->comm,
					task_state_str(thread->state),
					wchan_buf[0] ? wchan_buf : "(none)");

				/* Dump kernel stack if blocked (not running) */
				if (thread->state != 0 && thread->state != EXIT_ZOMBIE &&
				    task_curr(thread) == 0) {
					apex_dump_task_stack(thread);
				}
			}
		}
		rcu_read_unlock();

		/* Also dump all userspace processes if no zygote children */
		if (zy == 0 && apex_dump_count == 1) {
			pr_err("APEX_WDT: === All userspace processes ===\n");
			rcu_read_lock();
			for_each_process(task) {
				if (!(task->flags & PF_KTHREAD) && task->mm)
					pr_err("APEX_WDT:   pid=%d tgid=%d comm=%-16s state=%s parent=%s\n",
						task->pid, task->tgid, task->comm,
						task_state_str(task->state),
						task->parent ? task->parent->comm : "?");
			}
			rcu_read_unlock();
		}
	}

	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
}

/* ============================================================
 * vbmeta partition dump - verify block device read correctness
 * ============================================================ */
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>

extern struct hd_struct *get_part(const char *name);

static void apex_dump_vbmeta(void)
{
	struct block_device *bdev;
	struct gendisk *disk;
	struct hd_struct *part;
	struct buffer_head *bh;
	sector_t sector;
	char *data;
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

	/* blkdev_get_by_dev properly initializes the bdev (bdget alone is not enough) */
	bdev = blkdev_get_by_dev(disk_devt(disk), FMODE_READ, NULL);
	if (IS_ERR_OR_NULL(bdev)) {
		pr_err("APEX_VBMETA: blkdev_get_by_dev failed: %ld\n",
			PTR_ERR(bdev));
		return;
	}

	/* Read first 512 bytes of vbmeta partition using page cache */
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
		int ret;

		pr_err("APEX_VBMETA: __bread failed for sector %llu, trying page cache\n",
			(unsigned long long)sector);

		index = sector >> (PAGE_SHIFT - SECTOR_SHIFT);
		page = read_mapping_page(bdev->bd_inode->i_mapping, index, NULL);
		if (IS_ERR_OR_NULL(page)) {
			pr_err("APEX_VBMETA: read_mapping_page failed: %ld\n",
				PTR_ERR(page));
			blkdev_put(bdev, FMODE_READ);
			return;
		}

		kaddr = kmap(page);
		/* Copy to a local buffer to release the page early */
		{
			char local_data[512];
			memcpy(local_data, kaddr + ((sector & ((1 << (PAGE_SHIFT - SECTOR_SHIFT)) - 1)) * 512), 512);
			kunmap(page);
			put_page(page);
			data = local_data;
		}
		pr_err("APEX_VBMETA: page cache read succeeded, dumping data:\n");
	}

	/* Print hexdump of first 64 bytes */
	{
		int i;
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

		/* Check AVB magic "AVB0" */
		if (data[0] == 'A' && data[1] == 'V' && data[2] == 'B' && data[3] == '0') {
			u32 hash_size;
			hash_size = ((unsigned char)data[8] << 24) |
				    ((unsigned char)data[9] << 16) |
				    ((unsigned char)data[10] << 8) |
				    ((unsigned char)data[11]);
			pr_err("APEX_VBMETA: AVB magic OK! hash_size=%u (0x%x)\n",
				hash_size, hash_size);
		} else {
			pr_err("APEX_VBMETA: AVB magic NOT found! first 4 bytes: %02x %02x %02x %02x\n",
				(unsigned char)data[0], (unsigned char)data[1],
				(unsigned char)data[2], (unsigned char)data[3]);
		}
	}

	if (bh)
		brelse(bh);
	blkdev_put(bdev, FMODE_READ);
}

static int __init apex_debug_init(void)
{
	pr_err("APEX: apex_debug loaded. kernel=%s\n", utsname()->release);
	pr_err("APEX: tracking exec+exit, watchdog dumps stacks after 20s\n");

	/* Dump vbmeta partition to verify block device read */
	apex_dump_vbmeta();

	timer_setup(&apex_watchdog, apex_watchdog_fn, 0);
	mod_timer(&apex_watchdog, jiffies + 10 * HZ);
	return 0;
}
late_initcall(apex_debug_init);

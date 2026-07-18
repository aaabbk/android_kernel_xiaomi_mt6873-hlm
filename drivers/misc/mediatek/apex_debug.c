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

/* ============================================================
 * Hook 2: exit tracking
 * ============================================================ */
void apex_do_exit_hook(long code)
{
	struct task_struct *t = current;

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
 * Watchdog: dump blocked threads with stack traces
 * Fires every 10 seconds. After 15 seconds starts dumping
 * thread stacks for watched processes.
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
	if (!strncmp(task->comm, "vold", 4)) return 1;
	if (!strncmp(task->comm, "init", 4) && task->pid <= 2) return 1;
	/* Any D-state (TASK_UNINTERRUPTIBLE) userspace process is interesting */
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

	pr_err("APEX_WDT: t=%ds sf=%d zygote_kids=%d bootanim=%d sys_srv=%d\n",
		(int)(jiffies_to_msecs(jiffies) / 1000), sf, zy, ba, ss);

	/* Check mount points - critical for understanding vold failure */
	apex_check_mounts();

	/* After 8s, dump detailed thread status for watched processes */
	if (jiffies_to_msecs(jiffies) > 8000 || apex_dump_count > 0) {
		apex_dump_count++;
		pr_err("APEX_WDT: === Thread dump #%d ===\n", apex_dump_count);
		rcu_read_lock();
		for_each_process(task) {
			int nthreads = 0;
			struct task_struct *tmp;

			if (!apex_is_watch_target(task))
				continue;

			/* Count threads */
			for_each_thread(task, tmp)
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

				pr_err("APEX_WDT:   [%d] %s state=%s wchan=%s\n",
					thread->pid, thread->comm,
					task_state_str(thread->state),
					wchan_buf[0] ? wchan_buf : "(none)");

				/* Dump kernel stack if blocked (not running) */
				if (thread->state != 0 &&
				    thread->state != EXIT_ZOMBIE &&
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
						task->pid, task->tgid,
						task->comm,
						task_state_str(task->state),
						task->parent ?
						task->parent->comm : "?");
			}
			rcu_read_unlock();
		}
	}

	mod_timer(&apex_watchdog, jiffies + 5 * HZ);
}

/* ============================================================
 * vbmeta partition dump - verify block device read correctness
 * Reads the AVB vbmeta header and verifies the magic + hash_size.
 * ============================================================ */
static void apex_dump_vbmeta(void)
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
static void apex_dump_partitions(void)
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

		if (part->info && part->info->volname)
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
static void apex_check_metadata_part(void)
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
		if (p.mnt->mnt_sb->s_id)
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
	pr_err("APEX_MOUNT: === mount point check at t=%ds ===\n",
		(int)(jiffies_to_msecs(jiffies) / 1000));

	apex_check_mount("/metadata");
	apex_check_mount("/metadata/vold");
	apex_check_mount("/data");
	apex_check_mount("/system");
	apex_check_mount("/vendor");
	apex_check_mount("/apex");

	/* Also check specific files vold needs */
	{
		struct path p;
		int err;

		err = kern_path("/metadata/vold/checkpoint", 0, &p);
		if (err) {
			pr_err("APEX_MOUNT: /metadata/vold/checkpoint: NOT FOUND (err=%d)\n", err);
		} else {
			pr_err("APEX_MOUNT: /metadata/vold/checkpoint: EXISTS size=%lld\n",
				(long long)p.dentry->d_inode->i_size);
			path_put(&p);
		}

		/* Check binder devices - bootctrl HAL needs hwbinder */
		err = kern_path("/dev/binder", 0, &p);
		if (err)
			pr_err("APEX_MOUNT: /dev/binder: NOT FOUND (err=%d)\n", err);
		else {
			pr_err("APEX_MOUNT: /dev/binder: EXISTS\n");
			path_put(&p);
		}

		err = kern_path("/dev/hwbinder", 0, &p);
		if (err)
			pr_err("APEX_MOUNT: /dev/hwbinder: NOT FOUND (err=%d)\n", err);
		else {
			pr_err("APEX_MOUNT: /dev/hwbinder: EXISTS\n");
			path_put(&p);
		}

		err = kern_path("/dev/vndbinder", 0, &p);
		if (err)
			pr_err("APEX_MOUNT: /dev/vndbinder: NOT FOUND (err=%d)\n", err);
		else {
			pr_err("APEX_MOUNT: /dev/vndbinder: EXISTS\n");
			path_put(&p);
		}

		/* Check /dev/block/by-name/ symlinks (created by init) */
		err = kern_path("/dev/block/by-name/metadata", 0, &p);
		if (err)
			pr_err("APEX_MOUNT: /dev/block/by-name/metadata: NOT FOUND (err=%d)\n", err);
		else {
			pr_err("APEX_MOUNT: /dev/block/by-name/metadata: EXISTS\n");
			path_put(&p);
		}
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
 * Init
 * ============================================================ */
static int __init apex_debug_init(void)
{
	pr_err("APEX: apex_debug loaded. kernel=%s\n", utsname()->release);
	pr_err("APEX: tracking exec+exit, watchdog dumps stacks after 15s\n");

	/* Dump all partitions to verify metadata partition exists */
	apex_dump_partitions();

	/* Check metadata partition content */
	apex_check_metadata_part();

	/* Dump vbmeta partition to verify block device read */
	apex_dump_vbmeta();

	/* Dump kernel command line */
	apex_dump_cmdline();

	/* Initial mount check (most partitions not mounted yet at late_initcall,
	 * but /system and /vendor should be) */
	apex_check_mounts();

	/* Start watchdog - first fire at 5s to catch pre-vold state,
	 * then every 10s after */
	timer_setup(&apex_watchdog, apex_watchdog_fn, 0);
	mod_timer(&apex_watchdog, jiffies + 5 * HZ);
	return 0;
}
late_initcall(apex_debug_init);

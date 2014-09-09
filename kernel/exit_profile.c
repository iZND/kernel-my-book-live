/*
 * @file exit_profile.c
 *
 * @remark Copyright (c) 2012 Western Digital Corporation, Inc.
 */

#include <linux/kobject.h>
#include <linux/notifier.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/debugfs.h>

#include "exit_profile.h"

static int exit_profile_enabled = 0;

static unsigned long long boot_time = 0;


/*
 * log the process' statistics
 */
static int task_exit_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct task_struct *tsk = data;
	struct mm_struct *mm;

	unsigned long long start_time, this_time;
	struct timespec thistime;

	/* see the comment in fs/proc/task_mmu.c */
	unsigned long hiwater_rss;

	/* somewhat from fs/proc/array.c */
	char tcomm[sizeof(tsk->comm)];

	pr_debug("%s: called data %p, val %lu\n", __FUNCTION__, data, val);

	if (tsk == NULL) {
		printk(KERN_WARNING "%s: val %lu; data %p\n", __FUNCTION__,
		       val, data);
		return 0;
	}
	start_time = (unsigned long long)tsk->real_start_time.tv_sec * NSEC_PER_SEC +
	  tsk->real_start_time.tv_nsec;
	start_time = nsec_to_clock_t(start_time);  /* clock_t because there's no jiffies to nsec */
	thistime = CURRENT_TIME;
	this_time = (unsigned long long)thistime.tv_sec * NSEC_PER_SEC +
	  thistime.tv_nsec;
	this_time = nsec_to_clock_t(this_time);  /* clock_t because there's no jiffies to nsec */
	this_time -= boot_time;

	get_task_comm(tcomm, tsk);
	mm = tsk->mm;
	if (mm == NULL) {
		printk(KERN_WARNING "%s: tsk %p; mm %p\n", __FUNCTION__,
		       tsk, mm);
		return 0;
	}

	hiwater_rss = get_mm_rss(mm);
	if (hiwater_rss < mm->hiwater_rss) {
		hiwater_rss = mm->hiwater_rss;
	}

	printk(KERN_INFO "%s: Name %16s; VmHWM %8lu kB; start %llu; end %llu", __FUNCTION__,
	       tcomm,
	       hiwater_rss << (PAGE_SHIFT-10),
	       start_time,
	       this_time);

	if (exit_profile_enabled == 1) {
		printk("\n");
	} else if (exit_profile_enabled == 2) {
		printk("; pid %d; ppid %d\n",
		       tsk->pid,
		       (tsk->real_parent == NULL ? 0 : tsk->real_parent->pid));

		if ((tsk->group_leader == NULL) ||
		    (tsk->group_leader->pid == tsk->pid)) {
			printk("\n");
		} else {
			printk("; tgid %d\n", tsk->group_leader->pid);
		}
	} else {
		if (tsk->real_parent != NULL) {
			get_task_comm(tcomm, tsk->real_parent);
		}
		printk("; pid %d; ppid %d (%s)",
		       tsk->pid,
		       (tsk->real_parent == NULL ? 0 : tsk->real_parent->pid),
		       (tsk->real_parent == NULL ? "none" : tcomm));

		if ((tsk->group_leader == NULL) ||
		    (tsk->group_leader->pid == tsk->pid)) {
			printk("\n");
		} else {
			get_task_comm(tcomm, tsk->group_leader);
			printk("; tgid %d (%s)\n", tsk->group_leader->pid, tcomm);
		}
	}

	return 0;
}
static struct notifier_block task_exit_nb = {
	.notifier_call	= task_exit_notify,
};


/*
 * attach through /sys interfaces
 */
static ssize_t exit_profile_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", exit_profile_enabled);
}

static ssize_t exit_profile_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int value;

	if (sscanf(buf, "%du", &value) != 1) {
		printk(KERN_WARNING "%s: %s is not an integer\n",
		       __FUNCTION__, buf);
	}

	if (value != exit_profile_enabled) {
		if (exit_profile_enabled == 0) {
			int err;
			struct timespec boottime;

			/* do this once for all subsequent uses */
			getboottime(&boottime);
			boot_time = (unsigned long long)boottime.tv_sec * NSEC_PER_SEC +
			  boottime.tv_nsec;
			boot_time = nsec_to_clock_t(boot_time);  /* clock_t because there's no jiffies to nsec */
			pr_debug("%s: boot time %llu\n", __FUNCTION__, boot_time);

			err = profile_event_register(PROFILE_TASK_EXIT, &task_exit_nb);
			if (err) {
				printk(KERN_WARNING "%s: failed to register task exit notify (%d)\n",
				       __FUNCTION__, err);
			} else {
				exit_profile_enabled = value;
			}
		} else if (value == 0) {
			profile_event_unregister(PROFILE_TASK_EXIT, &task_exit_nb);
			exit_profile_enabled = 0;
		} else {  /* just update the value to change the information set */
			exit_profile_enabled = value;
		}
	}

	return count;
}
struct kobj_attribute exit_profile_attr =
	__ATTR(exit_profile, 0666, exit_profile_show, exit_profile_store);
/* EXPORT_SYMBOL_GPL(exit_profile_attr); */

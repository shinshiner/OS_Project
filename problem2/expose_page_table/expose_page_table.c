/*
 * This system call exposes page table from kernel space to user space
 */
#include <linux/list.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/init_task.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/rwlock_types.h>

#include <linux/magic.h>
#include <linux/kdebug.h>
#include <linux/bootmem.h>
#include <linux/kprobes.h>
#include <linux/mmiotrace.h>
#include <linux/perf_event.h>
#include <linux/hugetlb.h>
#include <linux/prefetch.h>
#include <linux/export.h>

#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/mman.h>

#include <linux/syscalls.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <linux/linkage.h>

MODULE_LICENSE("Dual BSD/GPL");
#define __NR_pstreecall 356
DEFINE_RWLOCK(buf_lock);

static int(*oldcall)(void);
#define pgd_c 1<<12

struct walk_info {
	int pgd_entry_counter;
	unsigned long offsetb[512], addressb[512];
	unsigned long pte_va;
};

unsigned long pgd_idx(unsigned long addr) { return ((addr) >> PGDIR_SHIFT);}

int my_pmd_entry(pmd_t *pmd, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct walk_info *my_walk_info = (struct walk_info *)walk->private;
	struct vm_area_struct *user_vma = current->mm->mmap;
	unsigned long pfn, my_pgd_index;
	int error;

	if (pmd == NULL)
		return 0;

	// get pfn of current PTE
	pfn = page_to_pfn(pmd_page(*pmd));
	if (pmd_bad(*pmd) || !pfn_valid(pfn))
		return -EINVAL;

	// do remap
	error = 0;
	error = remap_pfn_range(user_vma, my_walk_info->pte_va, pfn, PAGE_SIZE, user_vma->vm_page_prot);
	if (error) {
		printk("fail remap a pte\n");
		return error;
	}
	printk("ready to get pgd idx\n");

	// store address of current PTE in buffer
	my_pgd_index = pgd_idx(addr);
	printk("ready to construct pgd %lx\n",my_pgd_index);
	my_walk_info->offsetb[my_walk_info->pgd_entry_counter] = my_pgd_index;
	my_walk_info->addressb[my_walk_info->pgd_entry_counter] = my_walk_info->pte_va;
	my_walk_info->pgd_entry_counter++;
	printk("end construct pgd\n");

	// ready for next pte
	my_walk_info->pte_va += PAGE_SIZE;

	printk("remap a pte\n");
	return 0;
}

int expose_page_table (	pid_t pid, unsigned long fake_pgd,
						unsigned long fake_pmds, unsigned long page_table_addr,
						unsigned long begin_vaddr, unsigned long end_vaddr) {
	struct mm_walk walk;
	struct walk_info *my_walk_info;
	struct task_struct *target_tsk;
	int error = 0;
	int i;

	if (begin_vaddr >= end_vaddr)
		return -EINVAL;

	// get pid task
	rcu_read_lock();
	target_tsk = pid == -1 ? current : get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (target_tsk == NULL)
		return -EINVAL;
	my_walk_info = kcalloc(1, sizeof(struct walk_info), GFP_KERNEL);
	if (my_walk_info == NULL)
		return -ENOMEM;

	// hold semaphore for walking page table & remaping
	down_write(&current->mm->mmap_sem);
	if (pid != -1)
		down_write(&target_tsk->mm->mmap_sem);

	my_walk_info->pgd_entry_counter = 0;
	my_walk_info->pte_va = page_table_addr;

	walk.mm = target_tsk->mm;
	walk.private = my_walk_info;
	walk.pgd_entry = NULL;
	walk.pmd_entry = my_pmd_entry;
	walk.pte_entry = NULL;
	walk.pud_entry = NULL;
	walk.pte_hole = NULL;
	walk.hugetlb_entry = NULL;

	error = walk_page_range(begin_vaddr, end_vaddr, &walk);

	// release semaphore after walking page table
	if (pid != -1)
		up_write(&target_tsk->mm->mmap_sem);
	up_write(&current->mm->mmap_sem);

	if (error)
		return -1;

	// construct fake pgd in user space
	for (i = 0; i < my_walk_info->pgd_entry_counter; ++i) {
		unsigned long result;
		unsigned long *source, *dest;
		source = &(my_walk_info->addressb[i]);
		printk("get source %lx\n", my_walk_info->addressb[i]);
		dest = (unsigned long *)(fake_pgd + my_walk_info->offsetb[i] * sizeof(unsigned long));
		printk("dest = %lx\n",dest);
		result = copy_to_user(dest, source, sizeof(unsigned long));
		if (result) {
			printk("copy failed\n");
			error = -ENOMEM;
		}
	}

	kfree(my_walk_info);
	return error;
}

static int addsyscall_init(void){
	long *syscall = (long*)0xc000d8c4;
	oldcall = (int(*)(void))(syscall[__NR_pstreecall]);
	syscall[__NR_pstreecall] = (unsigned long)expose_page_table;
	printk(KERN_INFO "module load!\n");
	return 0;
}

static void addsyscall_exit(void){
	long *syscall = (long*)0xc000d8c4;
	syscall[__NR_pstreecall] = (unsigned long)oldcall;
	printk(KERN_INFO "module exit!\n");
}

module_init(addsyscall_init);
module_exit(addsyscall_exit);
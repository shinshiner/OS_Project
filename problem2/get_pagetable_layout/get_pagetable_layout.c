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
#define __NR_pstreecall 357
DEFINE_RWLOCK(buf_lock);

static int(*oldcall)(void);

extern struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

int get_pagetable_layout(struct pagetable_layout_info __user * pgtbl_info, int size) {
	if (size < sizeof(struct pagetable_layout_info)){
		printk("call get_pagetable_layout error!\n");
		return -EINVAL;
	}
	
	pgtbl_info->pgdir_shift = PGDIR_SHIFT;
	pgtbl_info->pmd_shift = PMD_SHIFT;
	pgtbl_info->page_shift = PAGE_SHIFT;

	printk("call get_pagetable_layout successfully!\n");

	return 0;
}

static int addsyscall_init(void){
	long *syscall = (long*)0xc000d8c4;
	oldcall = (int(*)(void))(syscall[__NR_pstreecall]);
	syscall[__NR_pstreecall] = (unsigned long)get_pagetable_layout;
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
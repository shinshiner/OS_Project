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

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};
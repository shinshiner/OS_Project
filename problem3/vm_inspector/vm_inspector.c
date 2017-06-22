/*
 * This application is used to dump a given range page table entry of target process
 */
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

#define ENTRY_SIZE	sizeof(unsigned long)
#define PGDIR_SHIFT	21
#define PMD_SHIFT	21
#define PAGE_SHIFT	12
#define PTRS_PER_PTE	512
#define PAGE_SIZE	4096
#define PTE_VALID	(1UL << 0)
#define PTE_PROC_NONE	(1UL << 1)
#define pte_present(pte)	(!!(pte & (PTE_VALID | PTE_PROC_NONE)))
#define PHY_MASK 0xFFFFF000

int pgd_index(unsigned long addr) { return ((addr) >> PGDIR_SHIFT);}
int pte_index(unsigned long addr) {	return ((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);}

int main(int argc, char **argv) {
	pid_t pid;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;

	size_t size_of_mmap = sysconf(_SC_PAGE_SIZE) * 4096;
	unsigned long *fake_pgd_base;
	unsigned long *page_table_addr;
	unsigned long pgd_max;
	unsigned long pte_max;
	int va_pgd_index;
	int va_pte_index;

	unsigned long pte;
	unsigned long va;
	unsigned long pa;

//***************************************input**************************************

	pid = strtol(argv[1], NULL, 10);
	begin_vaddr = strtoul(argv[2],'\0',16);
	end_vaddr = strtoul(argv[3],'\0',16);

//**********************************************************************************

//**********************************malloc space************************************

	// for pgd
	fake_pgd_base = mmap(NULL, size_of_mmap, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (page_table_addr == MAP_FAILED) {
		printf("line 69: mmap fail\n");
		return -1;
	}
	pgd_max = fake_pgd_base + size_of_mmap;

	//for pte
	page_table_addr = mmap(NULL, size_of_mmap, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (page_table_addr == MAP_FAILED) {
		printf("line 85: mmap fail\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}
	pte_max = page_table_addr + size_of_mmap;

//**********************************************************************************

//*********************************system call**************************************

	if (syscall(356, pid, fake_pgd_base, 0, page_table_addr, begin_vaddr, end_vaddr)) {
		printf("syscall 356 failed!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

//**********************************************************************************

//**************************************output**************************************

	va = begin_vaddr;
	while (va <= end_vaddr) {
		// get pgd index to find pte
		va_pgd_index = pgd_index(va);
		if ((fake_pgd_base + va_pgd_index * ENTRY_SIZE) >= pgd_max) {
			va += 4096;
			continue;
		}

		pte = *(fake_pgd_base + va_pgd_index);
		if (pte == 0) {
			va += 4096;
			continue;
		}

		// get pte index to find pa
		va_pte_index = pte_index(va);
		if ((pte + va_pte_index * ENTRY_SIZE) >= pte_max) {
			va += 4096;
			continue;
		}

		// get pa by interpret pte
		pa = *((unsigned long *)(pte + va_pte_index * ENTRY_SIZE));
		if (pa == 0) {
			va += 4096;
			continue;
		}

		// only output present page
		if (pte_present(pa) == 0) {
			va += 4096;
			continue;
		}

		printf("0x%lx --> 0x%lx\n", va, pa & PHY_MASK);

		// ready for next pte entry
		va += 4096;
		continue;
	}

//**********************************************************************************

	munmap((void *)page_table_addr, size_of_mmap);
	munmap((void *)fake_pgd_base, size_of_mmap);
	return 0;
}

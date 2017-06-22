/*
 * This application is used to translate a virtual in a process to a physical address
 */
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../headfile/get_pagetable_layout.h" //this should be set according to user himself

#define ENTRY_SIZE	sizeof(unsigned long)
#define PGDIR_SHIFT	21
#define PMD_SHIFT	21
#define PAGE_SHIFT	12
#define PTRS_PER_PTE	512
#define PAGE_SIZE	4096
#define PHY_MASK 0xFFFFF000

extern struct pagetable_layout_info;

//get pgd and pte index
int pgd_index(unsigned long addr) { return ((addr) >> PGDIR_SHIFT);}
int pte_index(unsigned long addr) {	return ((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);}

int main(int argc, char **argv) {
	pid_t pid;
	unsigned long va;

	size_t size_of_mmap = sysconf(_SC_PAGE_SIZE) * 4096;
	unsigned long *fake_pgd_base;
	unsigned long *page_table_addr;
	unsigned long pgd_max;
	unsigned long pte_max;
	int va_pgd_index;
	int va_pte_index;
	
	struct pagetable_layout_info pli;

	unsigned long pte;
	unsigned long pa;

//***************************************input**************************************

	pid = strtol(argv[1], NULL, 10);
	va = strtoul(argv[2],'\0',16);

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

	if (syscall(356, pid, fake_pgd_base, 0, page_table_addr, va, va + 1)) {
		printf("syscall 356 failed!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

	if (syscall(357, &pli, 12)) {
		printf("syscall 357 failed!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

//**********************************************************************************

//**************************************output**************************************

	printf("page layout infomation:\n");
	printf("  PGDIR_SHIFT = %d\n", pli.pgdir_shift);
	printf("  PMD_SHIFT = %d\n", pli.pmd_shift);
	printf("  PAGE_SHIFT = %d\n", pli.page_shift);

	// get pgd index to find pte
	va_pgd_index = pgd_index(va);
	if ((fake_pgd_base + va_pgd_index * ENTRY_SIZE) >= pgd_max){
		printf("This va is not in memory!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

	pte = *(fake_pgd_base + va_pgd_index);
	if (pte == 0){
		printf("This va is not in memory!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

	// get pte index to find pa
	va_pte_index = pte_index(va);
	if ((pte + va_pte_index * ENTRY_SIZE) >= pte_max){
		printf("This va is not in memory!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

	// get pa by interpret pte
	pa = *((unsigned long *)(pte + va_pte_index * ENTRY_SIZE));
	if (pa == 0){
		printf("This va is not in memory!\n");
		munmap((void *)page_table_addr, size_of_mmap);
		munmap((void *)fake_pgd_base, size_of_mmap);
		return -1;
	}

	printf("0x%lx --> 0x%lx\n", va, pa & PHY_MASK);

//**********************************************************************************

	munmap((void *)page_table_addr, size_of_mmap);
	munmap((void *)fake_pgd_base, size_of_mmap);
	return 0;
}

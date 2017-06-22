/*	
 * This application is used to test new page replacement algorithm
 */

#include <stdio.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>

int main(){
	long long size = 1<<15, i, j, k;
	int ***p, *q;
	printf("start to allocate space\n");
	p = malloc(size);
	for(i=0;i<size/8;++i){
		p[i] = malloc(size);
		for(j=0;j<size/8;++j){
			p[i][j] = malloc(size);
			for(k=0;k<size/8;++k)
				p[i][j][k] = k;
		}
	}

	for(i=0;i<size/8;++i){
		for(j=0;j<size/8;++j)
			free(p[i][j]);
		free(p[i]);
	}

	free(p);

	return 0;
}
/*	
 * This application is used to test vm_inspector
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
	printf("ready for i\n");
	scanf("%d",&i);
	printf("get i\n");
	q = malloc((1<<30)*(1<<30));
	for(i=0;i<1<<30;++i)
		q[i] = i;
	
	while(1);
	free(p);
	free(q);
	return 0;
}
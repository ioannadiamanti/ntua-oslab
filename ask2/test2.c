#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
int main(){
	int status;
	int fd = open("/dev/lunix0-temp",O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	char buf[10];
	pid_t p = fork();
	while(1){
		//if(p)wait(&status);
		int cnt = read(fd,buf,2);
		
		if (cnt < 0) {
			perror("read");
			exit(1);
		}
		else if (cnt == 0) printf("I am at end-of-file\n");
		//else printf("test2 read %d bytes",cnt);;
		else printf("test2 Process with pid = %d read %d bytes :",p, cnt);
		for(int i=0;i<cnt;i++)	printf("%c",buf[i]);
		printf("\n");
		//if(p==0) exit(0);
	}
	return 0;
}

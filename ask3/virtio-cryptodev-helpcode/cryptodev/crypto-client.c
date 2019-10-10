#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <crypto/cryptodev.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

#define BUF_SIZE        256
#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */

ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[]){
	int sd, port,retval,fd;
	ssize_t n;
	unsigned char buf[BUF_SIZE];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	struct timeval t;
	fd_set rfds,wfds;
	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;
	
	strcpy((char*)data.iv, "86f127b27f3498e554deef279d703f44");
	strcpy((char*)data.key, "fb2a177c8db85bd81f8cfa5466c377f1");

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	
	port = (int)strtol(argv[2],NULL,0);
	if(errno==EINVAL){
		printf("Invalid Operation\n");	
		exit(1);
	}
	if(errno==ERANGE){
		printf("Port Number out of range\n");
		exit(1);
	}
	
	
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	
	/*
	 * Get crypto session for AES128
	 */
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key= (unsigned char*)"fb2a177c8db85bd81f8cfa5466c377f1";
	
	
	cryp.len = sizeof(data.in);
	cryp.src = data.in;
	cryp.iv = data.iv;
	
	/*Open crypto device*/
	fd = open("/dev/cryptodev0", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}
	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}
	
	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");
	
	t.tv_sec=1;
	t.tv_usec=0;
	
	if (ioctl(fd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}
	cryp.ses = sess.ses;
	for (;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(0,&rfds);
		FD_SET(sd,&rfds);
		FD_SET(0,&wfds);
		FD_SET(sd,&wfds);
		retval=select(sd+1,&rfds,&wfds,NULL,&t);
		
		if(retval==-1) perror("select()");
		else if (retval){
			if(FD_ISSET(0,&rfds) && FD_ISSET(sd,&wfds)){
				n=read(0,buf,sizeof(buf));
				if (n < 0) {
					perror("read");
					exit(1);
				}

				if (n <= 0)
					break;

				if(n<sizeof(buf)) buf[n]='\0';
				else buf[n-1]='\0';
				memcpy(data.in,buf,sizeof(data.in));
				cryp.op = COP_ENCRYPT;
				cryp.dst =data.encrypted;
				if (ioctl(fd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}
				memcpy(buf,data.encrypted,sizeof(data.encrypted));
				if (insist_write(sd, buf,sizeof(data.encrypted)) != sizeof(data.encrypted)) {
					perror("write");
					exit(1);
				}
			}
			if(FD_ISSET(sd,&rfds) && FD_ISSET(0,&wfds)){
				n = read(sd, buf, sizeof(buf));
				if (n < 0) {
					perror("read");
					exit(1);
				}

				if (n <= 0)
					break;
				memcpy(data.in,buf,sizeof(data.in));
				cryp.op = COP_DECRYPT;
				cryp.dst = data.decrypted;
				if (ioctl(fd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}
				memcpy(buf,data.decrypted,sizeof(data.decrypted));
				if (insist_write(0, buf,strlen((char*)buf)) != strlen((char*)buf)) {
					perror("write");
					exit(1);
				}
			}	
			
		}
	}
	
	/* Finish crypto session */
	if (ioctl(fd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}
	return 0;
}


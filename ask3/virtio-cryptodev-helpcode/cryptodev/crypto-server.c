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



int main(void){
	unsigned char buf[BUF_SIZE];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd,retval,fd;
	ssize_t n;
	socklen_t len;
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
	
	t.tv_sec=1;
	t.tv_usec=0;
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);
	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/*Open crypto device*/
	fd = open("/dev/cryptodev0", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/cryptodev0)");
		return 1;
	}
	/*Initialize Session*/	
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
	
	
	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);
	
	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}
	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
		
		if (ioctl(fd, CIOCGSESSION, &sess)) {
			perror("ioctl(CIOCGSESSION)");
			return 1;
		}
		cryp.ses = sess.ses;
		/* We break out of the loop when the remote peer goes away */
		for (;;) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(0,&rfds);
			FD_SET(newsd,&rfds);
			FD_SET(0,&wfds);
			FD_SET(newsd,&wfds);
			retval=select(newsd+1,&rfds,&wfds,NULL,&t);
			if(retval == -1) perror("select()");
			else if(retval){
				if(FD_ISSET(newsd,&rfds) && FD_ISSET(0,&wfds)){
					n = read(newsd, buf, sizeof(buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from remote peer failed");
						else{
							fprintf(stderr, "Peer went away\n");
							break;
						}
					}
					memcpy(data.in,buf,sizeof(data.in));
					cryp.op = COP_DECRYPT;
					cryp.dst = data.decrypted;
					if (ioctl(fd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}
					memcpy(buf,data.decrypted,sizeof(data.decrypted));
					if (insist_write(0, buf,strlen((char*)buf)) != strlen((char*)buf)) {
						perror("write to stdout failed");
						break;
					}
				}
				if(FD_ISSET(0,&rfds) && FD_ISSET(newsd,&wfds)){
					n=read(0,buf,sizeof(buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from stdin failed");
						else{
							fprintf(stderr, "Peer went away\n");
							break;
						}
					}
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
					if (insist_write(newsd, buf,sizeof(data.encrypted)) != sizeof(data.encrypted)) {
						perror("write to remote peer failed");
						break;
					}
					
				}

				
			}
		}
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	
		/* Finish crypto session */
		if (ioctl(fd, CIOCFSESSION, &sess.ses)) {
			perror("ioctl(CIOCFSESSION)");
			return 1;
		}
	}

	/* This will never happen */
	return 1;
}

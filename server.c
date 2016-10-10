#include <pthread.h>

#include "header.h"

typedef struct {
	int sockfd;
	struct sockaddr_in ssh_addr;
	unsigned char *key;
} thread_param;

/******** server_thread() *********************
 There is a separate instance of this function
 for each connection.  It handles all communication
 once a connnection has been established.
 *****************************************/
void* server_thread(void *ptr)
{
	int n;
	int ssh_fd, ssh_done = 0;
	unsigned char buffer[BUF_SIZE];

	bzero(buffer, BUF_SIZE);

	if (!ptr) pthread_exit(0); 
	printf("New thread started\n");
	thread_param *params = (thread_param *)ptr;
	int sock = params->sockfd;
	struct sockaddr_in ssh_addr = params->ssh_addr;
	unsigned char *key = params->key;
	

	ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (connect(ssh_fd, (struct sockaddr *)&ssh_addr, sizeof(ssh_addr)) < 0) {
		printf("Connection to ssh failed!\n");
		pthread_exit(0);
	} else {
		printf("Connection to ssh established!\n");
	}
	
	int flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		printf("read sock 1 flag error!\n");
		printf("Closing connections and exit thread!\n");
		close(sock);
		close(ssh_fd);
		free(params);
		pthread_exit(0);
	}
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	flags = fcntl(ssh_fd, F_GETFL);
	if (flags == -1) {
		printf("read ssh_fd flag error!\n");
		close(sock);
		close(ssh_fd);
		free(params);
		pthread_exit(0);
	}
	fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);

	ctr_state state;
	AES_KEY aes_key;
	unsigned char iv[8];
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		exit(1);
	}

	while (1) {
		while ((n = read(sock, buffer, BUF_SIZE)) > 0) {
			if (n < 8) {
				printf("Packet length smaller than 8!\n");
				close(sock);
				close(ssh_fd);
				free(params);
				pthread_exit(0);
			}
			
			memcpy(iv, buffer, 8);
			unsigned char decryption[n-8];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer+8, decryption, n-8, &aes_key, state.ivec, state.ecount, &state.num);
			//printf("%.*s\n", n, buffer);

			write(ssh_fd, decryption, n-8);

			if (n < BUF_SIZE)
				break;
		};
		
		while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0) {
			if (n > 0) {
				if(!RAND_bytes(iv, 8)) {
					fprintf(stderr, "Error generating random bytes.\n");
					exit(1);
				}

				char *tmp = (char*)malloc(n + 8);
				memcpy(tmp, iv, 8);
				unsigned char encryption[n];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(tmp+8, encryption, n);
				
				usleep(900);

				write(sock, tmp, n + 8);
				
				free(tmp);
			}
			printf("INFO: Sending data to ssh client\n");
			
			if (ssh_done == 0 && n == 0)
				ssh_done = 1;
			
			if (n < BUF_SIZE)
				break;
		}

		if (ssh_done == 1)
			break;
	}

	printf("Closing connections. Exiting thread!\n");
	close(sock);
	close(ssh_fd);
	free(params);
	pthread_exit(0);
}

int start_server(struct sockaddr_in serv_addr, struct sockaddr_in ssh_addr, unsigned char *key)
{
	int sockfd, newsockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	thread_param *param;
	pthread_t thread;


	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	while (1) {
		param = (thread_param *)malloc(sizeof(thread_param));
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		param->sockfd = newsockfd;
		param->ssh_addr = ssh_addr;
		param->key = key;

		if (newsockfd > 0) {
			pthread_create(&thread, 0, server_thread, (void *)param);
			pthread_detach(thread);
		} else {
			error("ERROR on accept");
			free(param);
		}
	}
	return 0; /* shouldn't get here */
}

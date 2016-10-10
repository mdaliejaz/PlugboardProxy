
#include "header.h"

int start_client(struct sockaddr_in serv_addr, unsigned char *key)
{
	int sockfd, n;
	unsigned char buffer[BUF_SIZE];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR connecting");

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

	int flags = fcntl(sockfd, F_GETFL);
	if (flags == -1) {
		printf("read sockfd flag error!\n");
		close(sockfd);
	}
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	bzero(buffer, BUF_SIZE);

	ctr_state state;
	unsigned char iv[8];
	AES_KEY aes_key;

	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		exit(1);
	}

	while (1) {
		while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
			if (!RAND_bytes(iv, 8)) {
				printf("Error generating random bytes.\n");
				exit(1);
			}

			char *tmp = (char*)malloc(n + 8);
			memcpy(tmp, iv, 8);
			unsigned char encryption[n];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
			memcpy(tmp + 8, encryption, n);

			write(sockfd, tmp, n + 8);

			free(tmp);

			if (n < BUF_SIZE)
				break;
		}

		while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
			if (n < 8) {
				fprintf(stderr, "Packet length smaller than 8!\n");
				close(sockfd);
				return 0;
			}

			memcpy(iv, buffer, 8);
			unsigned char decryption[n - 8];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer + 8, decryption, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

			write(STDOUT_FILENO, decryption, n - 8);

			if (n < BUF_SIZE)
				break;
		}
	}
	return 0;
}

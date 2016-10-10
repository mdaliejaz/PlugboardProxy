
#include "header.h"

/*
 * Reference:
 * http://stackoverflow.com/questions/174531/easiest-way-to-get-files-contents-in-c
 */
unsigned char* read_keyfile(char* filename)
{
	unsigned char *buffer = NULL;
	long length;
	FILE *f = fopen (filename, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, f);
		}
		fclose (f);
	}
	return buffer;
}

int main(int argc, char *argv[])
{
	int opt, server_port = 0, dst_port;
	char *dst_addr = NULL;
	unsigned char *key = NULL;
	int is_server = 0;

	struct hostent *host;

	struct sockaddr_in sock_addr, ssh_addr;
	bzero(&sock_addr, sizeof(sock_addr));
	bzero(&ssh_addr, sizeof(ssh_addr));

	while ((opt = getopt(argc, argv, "l:k:h")) != -1) {
		switch (opt) {
		case 'l':
			is_server = 1;
			server_port = (int)strtol(optarg, NULL, 10);
			break;
		case 'k':
			key = read_keyfile(optarg);
			if (!key) {
				fprintf(stderr, "read key file failed!\n");
				return 0;
			}
			break;
		case 'h':
			fprintf(stdout, "pbproxy [-l port] -k keyfile destination port\n");
			exit(EXIT_SUCCESS);
		default:
			fprintf(stderr, "pbproxy [-l port] -k keyfile destination port!\n");
			exit(EXIT_FAILURE);
		}
	}
	if (key == NULL) {
		fprintf(stderr, "keyfile must be specified!\n");
		exit(EXIT_FAILURE);
	}
	if (optind + 2 != argc) {
		fprintf(stderr, "Insufficient number of arguments.\n");
		exit(EXIT_FAILURE);
	}

	dst_addr = argv[optind];
	dst_port = (int)strtol(argv[optind + 1], NULL, 10);

	printf("key = %s\n", key);
	printf("is_server %d\n", is_server);
	printf("server_port = %d\n", server_port);
	printf("dst_addr = %s\n", dst_addr);
	printf("dst_port = %d\n", dst_port);

	if ((host = gethostbyname(dst_addr)) == 0) {
		fprintf(stderr, "Could not get host by name!\n");
		exit(EXIT_FAILURE);
	}

	if (is_server == 1) {
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr.s_addr = htons(INADDR_ANY);
		sock_addr.sin_port = htons(server_port);

		ssh_addr.sin_family = AF_INET;
		ssh_addr.sin_port = htons(dst_port);
		ssh_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;
		start_server(sock_addr, ssh_addr, key);
	} else {
		sock_addr.sin_family = AF_INET;
		// bcopy((char *)host->h_addr, (char *)&sock_addr.sin_addr.s_addr, host->h_length);
		sock_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;
		
		sock_addr.sin_port = htons(dst_port);
		start_client(sock_addr, key);
	}

	free(key);
	exit(EXIT_SUCCESS);
}

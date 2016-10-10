#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUF_SIZE 4096

int start_server(struct sockaddr_in, struct sockaddr_in, unsigned char*);

int start_client(struct sockaddr_in, unsigned char*);

typedef struct {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
} ctr_state;

void init_ctr(ctr_state *state, const unsigned char iv[16]);

void error(char *);


#include "header.h"

void init_ctr(ctr_state *state, const unsigned char iv[16])
{
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	* first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

void error(char *msg)
{
	perror(msg);
	exit(0);
}

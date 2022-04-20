#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "common.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int sha384_hmac_afalg(char *input_buf, char *key_buf, char *alafg_buf)
{
	int i;
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "hmac(sha384)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4)] = {0};
	struct iovec iov;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, 48);

	opfd = accept(tfmfd, NULL, 0);

	write(opfd, input_buf, 1024);

	read(opfd, alafg_buf, 48);

#ifdef PRINT
	printf("AF_ALG RESULT:\n");
	for (i = 0; i < 48; i++) {
		printf("%02x ", (unsigned char)alafg_buf[i]);
	}
	printf("\n");
#endif

	close(opfd);
	close(tfmfd);

	return 0;
}

int sha384_hmac_openssl(char *input_buf, char *key_buf, char *openssl_buf)
{
	int i;

	HMAC(EVP_sha384(), key_buf, 48, input_buf, 1024, openssl_buf,NULL);

#ifdef PRINT
	printf("OPENSSL RESULT:\n");
	for (i = 0; i < 48; i++) {
		printf("%02x ", (unsigned char)openssl_buf[i]);
	}
	printf("\n");
#endif

	return 0;
}

int sha384_hmac_test()
{
	int ret;
	char alafg_buf[48];
	char openssl_buf[48];
	char key_buf[48];
	char input_buf[1024];

	for (int i = 0; i < 100; ++i)
	{
		rand_array(input_buf, 1024);
		rand_array(key_buf, 48);

		sha384_hmac_afalg(input_buf, key_buf, alafg_buf);
		sha384_hmac_openssl(input_buf, key_buf, openssl_buf);
		ret = array_equal(alafg_buf, openssl_buf, 48);
		if (ret < 0)
		{
			printf("SHA384 HMAC ERROR: AFALG AND OPENSSL RESULTS DIFFER\n");
			return -1;
		}
	}

	printf("SHA384 HMAC PASS\n");

	return 0;
}

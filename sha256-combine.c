#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "common.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int sha256_afalg(char *input_buf, char *alafg_buf)
{
	int i;
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha256"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4)] = {0};
	struct iovec iov;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	opfd = accept(tfmfd, NULL, 0);

	write(opfd, input_buf, 1024);

	read(opfd, alafg_buf, 32);

#ifdef PRINT
	printf("AF_ALG RESULT:\n");
	for (i = 0; i < 32; i++) {
		printf("%02x ", (unsigned char)alafg_buf[i]);
	}
	printf("\n");
#endif

	close(opfd);
	close(tfmfd);

	return 0;
}

int sha256_openssl(char *input_buf, char *openssl_buf)
{
	int i;
	SHA256(input_buf, 1024, openssl_buf);

#ifdef PRINT
	printf("OPENSSL RESULT:\n");
	for (i = 0; i < 32; i++) {
		printf("%02x ", (unsigned char)openssl_buf[i]);
	}
	printf("\n");
#endif

	return 0;
}

int sha256_test()
{
	int ret;
	char alafg_buf[32];
	char openssl_buf[32];
	char input_buf[1024];

	for (int i = 0; i < 100; ++i)
	{
		rand_array(input_buf, 1024);

		sha256_afalg(input_buf, alafg_buf);
		sha256_openssl(input_buf, openssl_buf);
		ret = array_equal(alafg_buf, openssl_buf, 32);
		if (ret < 0)
		{
			printf("SHA256 ERROR: AFALG AND OPENSSL RESULTS DIFFER\n");
			return -1;
		}
	}

	printf("SHA256 PASS\n");

	return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "common.h"

int aes_xts_afalg(char *input_buf, char *key_buf, char *iv_buf, char *alafg_buf)
{
	int i;
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "xts(aes)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct af_alg_iv *iv;
	struct iovec iov;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, 32);

	opfd = accept(tfmfd, NULL, 0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	iv = (void *)CMSG_DATA(cmsg);
	iv->ivlen = 16;
	memcpy(iv->iv, iv_buf, 16);

	iov.iov_base = input_buf;
	iov.iov_len = 64;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, alafg_buf, 64);
#ifdef PRINT
	printf("AF_ALG RESULT:\n");
	for (i = 0; i < 64; i++) {
		printf("%02x ", (unsigned char)alafg_buf[i]);
	}
	printf("\n");
#endif

	close(opfd);
	close(tfmfd);

	return 0;
}

int aes_xts_openssl(char *input_buf, char *key_buf, char *iv_buf, char *openssl_buf)
{
	int i;
	int mlen = 0;
	int flen = 0;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key_buf, iv_buf);

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	EVP_EncryptUpdate(ctx, openssl_buf, &mlen, input_buf, 64);

	EVP_EncryptFinal_ex(ctx, openssl_buf+mlen, &flen);

#ifdef PRINT
	printf("OPENSSL RESULT:\n");
	for (i = 0; i < 64; i++) {
		printf("%02x ", (unsigned char)openssl_buf[i]);
	}
	printf("\n");
#endif

	return 0;
}

int aes_xts_test()
{
	int ret;
	char alafg_buf[64];
	char openssl_buf[64];
	char key_buf[32];
	char iv_buf[16];
	char input_buf[64];

	for (int i = 0; i < 100; ++i)
	{
		rand_array(key_buf, 32);
		rand_array(iv_buf, 16);
		rand_array(input_buf, 64);

		aes_xts_afalg(input_buf, key_buf, iv_buf, alafg_buf);

		aes_xts_openssl(input_buf, key_buf, iv_buf, openssl_buf);
		ret = array_equal(alafg_buf, openssl_buf, 64);
		if (ret < 0)
		{
			printf("AES-XTS: AFALG AND OPENSSL RESULTS DIFFER\n");
			return -1;
		}
	}

	printf("AES-XTS PASS\n");

	return 0;
}

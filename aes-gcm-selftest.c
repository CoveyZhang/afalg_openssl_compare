#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "common.h"

int aes_gcm_afalg(char *input_buf, char *key_buf, char *iv_buf, char *alafg_buf)
{
	int i;
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "gcm(aes)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct af_alg_iv *iv;
	struct iovec iov;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, 16);
	setsockopt(tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 16);

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
	iv->ivlen = 12;
	memcpy(iv->iv, iv_buf, 12);

	iov.iov_base = input_buf;
	iov.iov_len = 64;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, alafg_buf, 80);
#ifdef PRINT
	printf("AF_ALG RESULT:\n");
	for (i = 0; i < 80; i++) {
		printf("%02x ", (unsigned char)alafg_buf[i]);
	}
	printf("\n");
#endif

	close(opfd);
	close(tfmfd);

	return 0;
}

int aes_gcm_afalg_de(char *input_buf, char *key_buf, char *iv_buf, char *de_buf)
{
	int i;
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "gcm(aes)"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct af_alg_iv *iv;
	struct iovec iov;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, 16);

	opfd = accept(tfmfd, NULL, 0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	iv = (void *)CMSG_DATA(cmsg);
	iv->ivlen = 12;
	memcpy(iv->iv, iv_buf, 12);

	iov.iov_base = input_buf;
	iov.iov_len = 80;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, de_buf, 64);
#ifdef PRINT
	printf("AF_ALG RESULT:\n");
	for (i = 0; i < 64; i++) {
		printf("%02x ", (unsigned char)de_buf[i]);
	}
	printf("\n");
#endif

	close(opfd);
	close(tfmfd);

	return 0;
}

int aes_gcm_test()
{
	int ret;
	char alafg_buf[80];
	char de_buf[64];
	char key_buf[16];
	char iv_buf[12];
	char input_buf[64];

	for (int i = 0; i < 100; ++i)
	{
		rand_array(key_buf, 16);
		rand_array(iv_buf, 12);
		rand_array(input_buf, 64);

		aes_gcm_afalg(input_buf, key_buf, iv_buf, alafg_buf);
		aes_gcm_afalg_de(alafg_buf, key_buf, iv_buf, de_buf);
		ret = array_equal(input_buf, de_buf, 64);
		if (ret < 0)
		{
			printf("AES-GCM: AFALG AND OPENSSL RESULTS DIFFER\n");
			return -1;
		}
	}

	printf("AES-GCM PASS\n");

	return 0;
}

int main()
{
	aes_gcm_test();
}

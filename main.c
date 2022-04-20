#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include "common.h"

int main()
{
	int ret;

	ret = aes_ecb_test();
	if (ret < 0)
		return ret;

	ret = aes_cbc_test();
	if (ret < 0)
		return ret;

	ret = aes_ctr_test();
	if (ret < 0)
		return ret;

	ret = aes_xts_test();
	if (ret < 0)
		return ret;

	ret = aes_ccm_test();
	if (ret < 0)
		return ret;

	ret = aes_gcm_test();
	if (ret < 0)
		return ret;

	ret = md5_test();
	if (ret < 0)
		return ret;

	ret = md5_hmac_test();
	if (ret < 0)
		return ret;

	ret = sha1_test();
	if (ret < 0)
		return ret;

	ret = sha1_hmac_test();
	if (ret < 0)
		return ret;

	ret = sha224_test();
	if (ret < 0)
		return ret;

	ret = sha224_hmac_test();
	if (ret < 0)
		return ret;

	ret = sha256_test();
	if (ret < 0)
		return ret;

	ret = sha256_hmac_test();
	if (ret < 0)
		return ret;

	ret = sha384_test();
	if (ret < 0)
		return ret;

	ret = sha384_hmac_test();
	if (ret < 0)
		return ret;

	ret = sha512_test();
	if (ret < 0)
		return ret;

	ret = sha512_hmac_test();
	if (ret < 0)
		return ret;

	ret = sm3_test();
	if (ret < 0)
		return ret;

	ret = sm3_hmac_test();
	if (ret < 0)
		return ret;

	return 0;
}
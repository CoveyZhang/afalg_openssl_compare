#ifndef _COMMON_H_
#define _COMMON_H_
#endif

int array_equal(char *buf1, char *buf2, int n);

int rand_array(char *buf, int n);

int aes_ecb_test();

int aes_cbc_test();

int aes_ctr_test();

int aes_xts_test();

int aes_ccm_test();

int aes_gcm_test();

int md5_test();

int md5_hmac_test();

int sha1_test();

int sha1_hmac_test();

int sha224_test();

int sha224_hmac_test();

int sha256_test();

int sha256_hmac_test();

int sha384_test();

int sha384_hmac_test();

int sha512_test();

int sha512_hmac_test();

int sm3_test();

int sm3_hmac_test();

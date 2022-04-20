LIB = -L/home/covey/crypto/openssl-1.1.1i/output/lib
#PRINT = -DPRINT
PRINT = -DPRINT -DPRINT_DETAIL

main: main.o aes-ecb-combine.o aes-cbc-combine.o common.o\
      aes-ctr-combine.o aes-xts-combine.o aes-ccm-combine.o\
      aes-gcm-combine.o md5-combine.o md5-hmac-combine.o\
      sha1-hmac-combine.o sha1-combine.o sha224-combine.o\
      sha224-hmac-combine.o sha256-combine.o sha256-hmac-combine.o\
      sha384-combine.o sha384-hmac-combine.o sha512-combine.o\
      sha512-hmac-combine.o sm3-combine.o sm3-hmac-combine.o

	gcc -o main main.o aes-cbc-combine.o\
		aes-ecb-combine.o aes-ctr-combine.o\
		aes-xts-combine.o aes-ccm-combine.o\
		aes-gcm-combine.o md5-combine.o md5-hmac-combine.o\
		sha1-combine.o sha1-hmac-combine.o\
		sha224-combine.o\
		sha224-hmac-combine.o sha256-combine.o sha256-hmac-combine.o\
		sha384-combine.o sha384-hmac-combine.o sha512-combine.o\
		sha512-hmac-combine.o sm3-combine.o sm3-hmac-combine.o\
		common.o $(LIB) -lcrypto $(PRINT)

sm3-hmac-combine.o: sm3-hmac-combine.c
	gcc -c sm3-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sm3-combine.o: sm3-combine.c
	gcc -c sm3-combine.c $(LIB) -lcrypto $(PRINT)

sha512-hmac-combine.o: sha512-hmac-combine.c
	gcc -c sha512-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sha512-combine.o: sha512-combine.c
	gcc -c sha512-combine.c $(LIB) -lcrypto $(PRINT)

sha384-hmac-combine.o: sha384-hmac-combine.c
	gcc -c sha384-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sha384-combine.o: sha384-combine.c
	gcc -c sha384-combine.c $(LIB) -lcrypto $(PRINT)

sha256-hmac-combine.o: sha256-hmac-combine.c
	gcc -c sha256-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sha256-combine.o: sha256-combine.c
	gcc -c sha256-combine.c $(LIB) -lcrypto $(PRINT)

sha224-hmac-combine.o: sha224-hmac-combine.c
	gcc -c sha224-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sha224-combine.o: sha224-combine.c
	gcc -c sha224-combine.c $(LIB) -lcrypto $(PRINT)

sha1-hmac-combine.o: sha1-hmac-combine.c
	gcc -c sha1-hmac-combine.c $(LIB) -lcrypto $(PRINT)

sha1-combine.o: sha1-combine.c
	gcc -c sha1-combine.c $(LIB) -lcrypto $(PRINT)

md5-hmac-combine.o: md5-hmac-combine.c
	gcc -c md5-hmac-combine.c $(LIB) -lcrypto $(PRINT)

md5-combine.o: md5-combine.c
	gcc -c md5-combine.c $(LIB) -lcrypto $(PRINT)

aes-gcm-combine.o: aes-gcm-combine.c
	gcc -c aes-gcm-combine.c $(LIB) -lcrypto $(PRINT)

aes-ccm-combine.o: aes-ccm-combine.c
	gcc -c aes-ccm-combine.c $(LIB) -lcrypto $(PRINT)

aes-xts-combine.o: aes-xts-combine.c
	gcc -c aes-xts-combine.c $(LIB) -lcrypto $(PRINT)

aes-ctr-combine.o: aes-ctr-combine.c
	gcc -c aes-ctr-combine.c $(LIB) -lcrypto $(PRINT)

aes-cbc-combine.o: aes-cbc-combine.c
	gcc -c aes-cbc-combine.c $(LIB) -lcrypto $(PRINT)

aes-ecb-combine.o: aes-ecb-combine.c
	gcc -c aes-ecb-combine.c $(LIB) -lcrypto $(PRINT)

common.o: common.c
	gcc -c common.c $(PRINT) 

.PHONY:clean
clean:
	rm -f *.o

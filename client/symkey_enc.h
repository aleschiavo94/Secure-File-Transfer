#ifndef SYMKEY_H
#define SYMKEY_H

#include "include.h"

int symmetric_encryption(unsigned char* inbuf, int inbuf_len, unsigned char* key, 
	unsigned char*& outbuf, int& len_out, unsigned char*& iv_out);

int symmetric_decryption(unsigned char* ciphertext_in, int cipherlen_in, unsigned char* key, 
	unsigned char* iv_in, unsigned char*& plaintext, int& plaintext_len);

int HMAC(unsigned char* key, int keylen, unsigned char* inbuf, int inbuf_len, 
							unsigned char*& outbuf, int& outlen);

int HMAC_check(unsigned char* received_digest, unsigned char* key, int keylen,
												unsigned char* inbuf, int inbuf_len);

#endif
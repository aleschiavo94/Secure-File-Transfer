#include "symkey_enc.h"

int symmetric_encryption(unsigned char* inbuf, int inbuf_len, unsigned char* key, 
	unsigned char*& outbuf, int& len_out, unsigned char*& iv_out){

	int ret;

		//generating iv
	size_t iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	unsigned char* iv = new unsigned char[iv_size];
	RAND_poll();
	RAND_bytes(iv, iv_size);
	
		//allocating sym encryption context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int outlen;

		//allocating buffer for ciphertext
	int ciphertext_buffsize = (inbuf_len + 16);
	unsigned char* ciphertext = new unsigned char[ciphertext_buffsize];
	int cipherlen;

		//actual encryption
	ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
	if(ret == 0){
		cerr << " !!! error EncryptInit()" << endl;
		delete[] iv;
		delete[] ciphertext;
		return 0;
	}
	ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, inbuf, inbuf_len);
	if(ret == 0){
		cerr << " !!! error EncryptUpdate()" << endl;
		delete[] iv;
		delete[] ciphertext;
		return 0;
	}
	cipherlen = outlen;
	EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
	if(ret == 0){
		cerr << " !!! error EncryptFinal()" << endl;
		delete[] iv;
		delete[] ciphertext;
		return 0;
	}
	cipherlen += outlen;

		//context deallocation
	EVP_CIPHER_CTX_free(ctx);

	outbuf = ciphertext;
	len_out = cipherlen;
	iv_out = iv;
	return 1;
}

int symmetric_decryption(unsigned char* ciphertext_in, int cipherlen_in, unsigned char* key, 
			unsigned char* iv_in, unsigned char*& plaintext, int& plaintext_len){

	int ret;
	int plainlen;
	int outlen;

	//decryption context initialization
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv_in);
	if(ret == 0){
		cerr << " !!! error DecryptFinal()" << endl;
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext_in, cipherlen_in);
	if(ret == 0){
		cerr << " !!! error DecryptFinal()" << endl;
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	plainlen = outlen;
	ret = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
	if(ret == 0){
		cerr << " !!! error DecryptFinal()" << endl;
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	plainlen += outlen;
	plaintext_len = plainlen;

	//context deallocation
	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

int HMAC(unsigned char* key, int keylen, unsigned char* inbuf, int inbuf_len, 
							unsigned char*& outbuf, int& outlen){
	int ret;	

		//allocating keyed-hashing context
   	HMAC_CTX* hmac_ctx = HMAC_CTX_new();

   		//allocating buffer for digest
   	unsigned char* hmac_digest = new unsigned char[EVP_MD_size(EVP_sha256())];
   	unsigned int hmac_digest_len;

   		//HMAC
   	ret = HMAC_Init(hmac_ctx, key, keylen, EVP_sha256());
   	if(ret == 0){
		cerr << " !!! error HMAC_Init()" << endl;
		delete[] hmac_digest;
		return 0;
	}
   	ret = HMAC_Update(hmac_ctx, inbuf, inbuf_len);
   	if(ret == 0){
		cerr << " !!! error HMAC_Update()" << endl;
		delete[] hmac_digest;
		return 0;
	}
   	ret = HMAC_Final(hmac_ctx, hmac_digest, &hmac_digest_len);
   	if(ret == 0){
		cerr << " !!! error HMAC_Final" << endl;
		delete[] hmac_digest;
		return 0;
	}

   		//context deallocation
   	HMAC_CTX_free(hmac_ctx);

   	outbuf = hmac_digest;
   	outlen = hmac_digest_len;
   	return 1;
}

int HMAC_check(unsigned char* received_digest, unsigned char* key, int keylen,
												unsigned char* inbuf, int inbuf_len){
	//compute the digest
	unsigned char* computed_digest = new unsigned char[EVP_MD_size(EVP_sha256())];
	int digest_len;

	HMAC(key, keylen, inbuf, inbuf_len, computed_digest, digest_len);

	//digest verifying
	int unequal;
	unequal = CRYPTO_memcmp(computed_digest, received_digest, digest_len);
	if(unequal){
		//digests are different
		cout << " Error CRYPTO_memcmp()" << endl;
		delete[] computed_digest;
		return 0;
	}
	delete[] computed_digest;
	return 1;
}
#ifndef PUBKEY_H
#define PUBKEY_H

#include "include.h"

void import_valid_subject_names(const char* filename, vector<string> &names);

string get_subject_name(X509* cert);

int verify_subject_name(X509* cert, vector<string> valid_subject_names);

X509* import_cert(const char* filename);

void import_old_nonces(const char* filename, vector<string> &old_nonces);

int generate_fresh_nonce(unsigned char* &out_nonce);

EVP_PKEY* import_RSA_PKEY(const char* filename);

X509_CRL* import_crl(const char* filename);

X509_STORE* init_store(X509* CA_cert, X509_CRL* crl);

int verify_cert(X509_STORE* store, X509* cert);

int init_public_key_enc(EVP_PKEY* &prvkey, X509* &CA_cert, X509_CRL* &CA_crl, X509_STORE* &store, 
																			vector<string> valid_subject_names);

int generate_symmetric_key(unsigned char*& Ksc);

int build_digital_envelope(EVP_PKEY* client_pubkey, unsigned char* Ksc, unsigned char*& ciphertext_out, int& cipherlen_out);

int send_ds_m4(EVP_PKEY* prvkey, unsigned char* m4_plain, int m4_plain_len, int sock);

int verify_signature(unsigned char* msg, int msg_size, EVP_PKEY* server_pubkey);

#endif
#ifndef PUBKEY_H
#define PUBKEY_H

#include "include.h"

void import_valid_subject_names(const char* filename, vector<string> &names);

void import_old_nonces(const char* filename, vector<string> &old_nonces);

string get_subject_name(X509* cert);

int verify_subject_name(X509* cert, vector<string> valid_subject_names);

X509* import_cert(const char* filename);

EVP_PKEY* import_RSA_PKEY(const char* filename);

X509_CRL* import_crl(const char* filename);

X509_STORE* init_store(X509* CA_cert, X509_CRL* crl);

int verify_cert(X509_STORE* store, X509* cert);

int init_public_key_enc(EVP_PKEY* &prvkey, X509* &CA_cert, X509_CRL* &CA_crl, X509_STORE* &store, 
																			vector<string> valid_subject_names);

int generate_fresh_nonce(unsigned char* &out_nonce);

int send_ds_nonce(EVP_PKEY* prvkey, unsigned char* nonce, int sock);

int verify_signature(unsigned char* msg, int msg_size, EVP_PKEY* server_pubkey);

int get_symmetric_key(unsigned char* msg, EVP_PKEY* prvkey, unsigned char*& sym_key);

#endif
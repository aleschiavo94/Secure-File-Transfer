#ifndef TCP_H
#define TCP_H

#include "include.h"

int send_TCP(int sock, unsigned char*& buff, uint16_t buff_size, unsigned char* key, int keylen);

int receive_TCP(int sock, unsigned char*& buff, uint16_t& buff_size, unsigned char* key, int keylen);

int receive_cert_nonce (int sock, X509** client_cert, unsigned char** client_nonce);

int send_cert_nonce(int sock, unsigned char* server_nonce);

#endif
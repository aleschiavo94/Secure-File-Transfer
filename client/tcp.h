#ifndef TCP_H
#define TCP_H

#include "include.h"

int send_TCP(int sock, unsigned char*& buff, uint16_t buff_size, unsigned char* key, int keylen);

int receive_TCP(int sock, unsigned char*& buff, uint16_t& length, unsigned char* key, int keylen);

int receive_cert_nonce(int sock, X509** server_cert, unsigned char** server_nonce);

int send_cert_nonce(int sock, unsigned char* client_nonce);

#endif
#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#include "include.h"

int execute_download(string command, int sock, uint32_t& counter, unsigned char* key);

int secure_recv_msgfileinfo(int sock, unsigned char* key, int key_size,
 									uint32_t& counter_server, unsigned char*& msg_fileinfo);

int secure_recv_msgfilechunk(int sock, int chunk_number, unsigned char* key, 
								uint32_t& counter_server, unsigned char*& decrypted_chunk_out);

#endif
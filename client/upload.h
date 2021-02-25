#ifndef UPLOAD_H
#define UPLOAD_H

#include "include.h"

int execute_upload(string command, int sock, uint32_t& counter, unsigned char* key);

int secure_send_msgfileinfo(int sock, unsigned char* key, unsigned char* name_file, 
											unsigned char* file_size, uint32_t& counter_cl);

int secure_send_msgfilechunk(int sock, char* chunk, int msg_len, unsigned char* key, uint32_t& counter_cl);

#endif
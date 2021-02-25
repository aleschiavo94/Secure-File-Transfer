#ifndef SESSION_H
#define SESSION_H

#include "include.h"

unsigned char* get_then_incr_counter(uint32_t& actual_counter_value);

int counter_check_then_incr(uint32_t& counter_server, uint32_t& counter_received);

int is_command_valid(string command);

int receive_message(string& command, int sock, uint32_t& counter, unsigned char* key);

int send_message(string command, int sock, uint32_t& counter, unsigned char* Ksc);

int execute_command(string command, int sock, uint32_t& counter, unsigned char* Ksc);

#endif
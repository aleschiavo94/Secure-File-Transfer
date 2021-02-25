#include "session.h"
#include "pubkey_enc.h"
#include "list_file.h"
#include "upload.h"
#include "download.h"
#include "quit.h"

unsigned char* incr_counter(uint32_t& actual_counter_value){
	actual_counter_value++;
	unsigned char *counter_value = new unsigned char[sizeof(uint32_t)];
	*((int*)counter_value) = htonl(actual_counter_value);

	return counter_value;
}

int counter_incr_then_check(uint32_t& counter, uint32_t& counter_received){
	counter++;
	if(counter == counter_received){
		return 1;
	}
	return 0;
}

int is_command_valid(string command){

	for(unsigned int i = 0; i < commands.size(); ++i){
		if( command.compare(commands[i])==0 ) return 1;
	}

	return 0;
}

int receive_message(string& command, int sock, uint32_t& counter, unsigned char* key){
	// retrieving command from client
	// message : <iv | counter | {command}_ksc | hmac[iv|counter|{command}_ksc] >

	int counter_size = sizeof(uint32_t);
	int hashed_size = 32;
	int iv_size = 16;
	int ret;

	unsigned char* message = NULL;
	uint16_t message_size = 0;
	
	ret = receive_TCP(sock, message, message_size, key, 16);
	if(ret == 0 || ret == -1){
		return ret;
	}

		//retrieve hmac[iv | counter|{command}_ksc]
	unsigned char* hashed = new unsigned char[hashed_size];
	memcpy(hashed, (message + message_size - hashed_size), hashed_size);

		//retieve iv| counter | {command}_ksc
	int inbuf_size = message_size - hashed_size;
	unsigned char* inbuf = new unsigned char[inbuf_size];
	memcpy((void*)inbuf, message, inbuf_size);

		//HMAC_check
	ret = HMAC_check(hashed, key, 16, inbuf, inbuf_size);
	if(ret == 0){
		cerr<<"Error HMAC_check()"<<endl;
		delete[] hashed;
		delete[] inbuf;
		return 0;
	}

		//retrieve counter sent from client
	unsigned char* received_counter = NULL;
	received_counter = new unsigned char[counter_size];
	memcpy((void*)received_counter, (message + iv_size), counter_size);
	uint32_t received_counter_ui = ntohl(*((int*)received_counter));

		//check counter received
	if(counter_incr_then_check(counter, received_counter_ui)==0){
		cout << "!!! incorrect counter value received\n";
		cout <<"act: "<<counter<<" rec: "<<received_counter_ui<<endl;	
		//send msg to resend file_info
			//...
		return 0;
	}

		//retrieve iv for command decryption
	unsigned char* iv = new unsigned char[iv_size];
	memcpy(iv, message, iv_size);

		//decryption {command}_ksc
			//retrieve {command}_ksc
	unsigned char* enc_command = NULL;
	int enc_command_size = message_size - iv_size - counter_size - 32;
	enc_command = new unsigned char[enc_command_size];
	memcpy((void*)enc_command, (message + iv_size + counter_size), enc_command_size);

	int plainlen;
	unsigned char* plaintext = new unsigned char[enc_command_size];

	ret = symmetric_decryption(enc_command, enc_command_size, key, iv, plaintext, plainlen);
	if( ret == 0){
		cerr<<"Error symmetric_decryption()"<<endl;
		delete[] iv;
		delete[] hashed;
		delete[] enc_command;
		delete[] inbuf;
		return 0;
	}

	string tmp ((const char*)plaintext);
	tmp.resize(plainlen);
	command = tmp;

	delete[] plaintext;
	delete[] iv;
	delete[] hashed;
	delete[] enc_command;
	delete[] inbuf;

	return 1;
}

int send_message(string command, int sock, uint32_t& counter, unsigned char* Ksc){
	// preparing message with command to send to the server
	// message : <iv, counter, {command}_ksc, hmac[iv|counter|{command}_ksc] >

	int ret;

	unsigned char* counter_buff = incr_counter(counter);
	int counter_size = sizeof(uint32_t);

	int command_buf_size = command.size();
	unsigned char* command_buf = new unsigned char[command_buf_size];
	memcpy(command_buf, command.c_str(), command_buf_size);

	int enc_command_size;
	unsigned char* enc_command = NULL;

	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	unsigned char* iv = new unsigned char[iv_size];

	symmetric_encryption(command_buf, command_buf_size, Ksc, enc_command, enc_command_size, iv);

	int to_be_hashed_size = counter_size + enc_command_size + iv_size;
	unsigned char* to_be_hashed = new unsigned char[to_be_hashed_size];
	memcpy(to_be_hashed, iv, iv_size);
	memcpy(to_be_hashed + iv_size, counter_buff, counter_size);
	memcpy(to_be_hashed + iv_size + counter_size, enc_command, enc_command_size);
	

	int hashed_size;
	unsigned char* hashed = NULL;

	HMAC(Ksc, 16, to_be_hashed, to_be_hashed_size, hashed, hashed_size);

	int message_size = iv_size + counter_size + enc_command_size + hashed_size;
	unsigned char* message = new unsigned char[message_size];
	memcpy(message, iv, iv_size);
	memcpy(message + iv_size, counter_buff, counter_size);
	memcpy(message + iv_size + counter_size, enc_command, enc_command_size);
	memcpy(message + iv_size + counter_size + enc_command_size, hashed, hashed_size);

	ret = send_TCP(sock, message, message_size, Ksc, 16); 
		if(ret == 0){
			delete[] counter_buff;
			delete[] message;
			delete[] to_be_hashed;
			delete[] iv;
			delete[] command_buf;
			return 0;
		}

	delete[] counter_buff;
	delete[] message;
	delete[] to_be_hashed;
	delete[] iv;
	delete[] command_buf;
	return 1;
}

int execute_command(string command, int sock, uint32_t& counter, unsigned char* Ksc){

	int ret;

	if (command == "list")
	{
	    ret = execute_list(command, sock, counter, Ksc);
	    if(ret == 0){
	    	cerr<<"Error in execute_list()"<<endl;
	    	return 0;
	    }
	    return 1;
	}
	else if (command == "upload")
	{ 
		ret = execute_upload(command, sock, counter, Ksc);
	    if(ret == 0){
	    	cerr<<"Error in execute_upload()"<<endl;
	    	return 0;
	    }
	    return 1;
	}
	else if (command == "download") 
	{
		ret = execute_download(command, sock, counter, Ksc);
	    if(ret == 0){
	    	cerr<<"Error in execute_download()"<<endl;
	    	return 0;
	    }
	    return 1;
	}
	else // command is quit
	{
		ret = execute_quit(command, sock, counter, Ksc);
	    if(ret == 0){
	    	cerr<<"Error in execute_upload()"<<endl;
	    	return 0;
	    }
	    return -1;
	}
	return 0;
}

#include "upload.h"

int secure_send_msgfileinfo(int sock, unsigned char* key, unsigned char* name_file, 
										 unsigned char* file_size, uint32_t& counter_cl){

	/*iv|counter|{file_name, file_size}Ksc|HMAC[iv|counter|{file_name, file_size}Ksc]*/

		//message composition: file_name|file_size
	unsigned char* file_info;
	int file_name_len = 100;
	int file_size_len = sizeof(int);
	file_info = new unsigned char[file_name_len + file_size_len];
	memcpy((void*)file_info, name_file, file_name_len);
	memcpy((void*)(file_info + file_name_len), file_size, file_size_len);

		//file_name|file_size encryption with Ksc
	unsigned char* file_info_ciphertext = new unsigned char[file_name_len + file_size_len + 16];
	int file_info_ciphertext_len;

	unsigned char* iv = NULL;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	iv = new unsigned char[iv_size];

	bool success;
	success = symmetric_encryption(file_info, (file_name_len + file_size_len), key, 
										file_info_ciphertext, file_info_ciphertext_len, iv);
	if(!success){
		cerr << "!!! error in symmetric_encryption of file_info msg." << endl;
		delete[] file_info_ciphertext;
		delete[] iv;
		return 0;
	}

		//message composition: iv|counter|{file_name, file_size}Ksc
	unsigned char* counter_value1 = incr_counter(counter_cl);
	int counter_value_len = sizeof(uint32_t);

	//cout << endl << "contatore: " <<  ntohl(*((int*)counter_value1));

	unsigned char* msg5 = NULL;
	int msg5_len = (counter_value_len + file_info_ciphertext_len + iv_size);
	msg5 = new unsigned char[msg5_len];
	memcpy((void*)msg5, iv, iv_size);
	memcpy((void*)(msg5 + iv_size), counter_value1, counter_value_len);
	memcpy((void*)(msg5 + iv_size + counter_value_len), file_info_ciphertext, file_info_ciphertext_len);

	//computation HMAC[iv|counter|{file_name, file_size}Ksc]
   		//allocating buffer for digest
   	unsigned char* msg5_digest;
   	msg5_digest = new unsigned char[EVP_MD_size(EVP_sha256())];
   	int msg5_digest_len;

	success = HMAC(key, 16, msg5, msg5_len, msg5_digest, msg5_digest_len);
	if(!success){
		cerr << "!!! error in calculating HMAC[counter|{file_name, file_size}Ksc]" << endl;
		delete[] msg5;
		delete[] msg5_digest; 
		return 0;
	}

	//actual send to server msg: iv|counter|{file_name, file_size}Ksc|HMAC[iv|counter|{file_name, file_size}Ksc]
		//message composition
	unsigned char* msg6 = NULL;
	int msg6_size = msg5_len + msg5_digest_len;
	msg6 = new unsigned char[msg6_size];
	memcpy((void*)msg6, msg5, msg5_len);
	memcpy((void*)(msg6 + msg5_len), msg5_digest, msg5_digest_len);

		//send
	int ret;
	ret = send_TCP(sock, msg6, msg6_size, key, 16); 
	if(ret == 0){
		cerr << "!!! error in sending counter|{file_name, file_size}Ksc|HMAC[counter|{file_name, file_size}Ksc]\n";
		close(sock);
		delete[] msg6;
		return 0;
	}


	delete[] iv;
	delete[] file_info;
	delete[] file_info_ciphertext;
	delete[] msg5;
	delete[] msg5_digest;
	delete[] msg6;

	return 1;
}

int secure_send_msgfilechunk(int sock, char* chunk, int msg_len, unsigned char* key, uint32_t& counter_cl){

	bool success;
	// iv | counter | {file_chunk}Ksc | HMAC[iv | counter | {file_chunk}Ksc]
			
		//chunk encryption 
	unsigned char* chunk_ciphertext = NULL;
	chunk_ciphertext = new unsigned char[msg_len + 16];
	int chunk_cipherlen;

	unsigned char* iv = NULL;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	iv = new unsigned char[iv_size];
			
	success = symmetric_encryption((unsigned char*)chunk, msg_len, key, 
													chunk_ciphertext, chunk_cipherlen, iv);
	if(!success){
		cerr << "!!! error in symmetric_encryption of the chunk" << endl;
		return 0;
	}

	//computing HMAC[iv | counter | {file_chunk}Ksc]
		//building message: iv | counter | {file_chunk}Ksc

			//counter update
	unsigned char* counter_value = incr_counter(counter_cl);
		
	unsigned char* inbuf;
	int inbuf_len = chunk_cipherlen + sizeof(uint32_t) + iv_size;
	inbuf = new unsigned char[inbuf_len];
	memcpy((void*)inbuf, iv, iv_size);
	memcpy((void*)(inbuf+ iv_size), counter_value, sizeof(uint32_t));
	memcpy((void*)(inbuf + iv_size + sizeof(uint32_t)), chunk_ciphertext, chunk_cipherlen);

		//allocating buffer for digest
	unsigned char* hmac_digest;
	hmac_digest = new unsigned char[EVP_MD_size(EVP_sha256())];
	int hmac_digest_len;

		//actual HMAC
	success = HMAC(key, 16, inbuf, inbuf_len, hmac_digest, hmac_digest_len);
	if(!success){
		cerr << "!!! error in calculating HMAC[counter | {file_chunk}Ksc]" << endl;
		return 0;
	}


	//composition message to send: <iv | counter | {file_chunk}Ksc | HMAC[iv | counter | {file_chunk}Ksc]>
	unsigned char* chunk_msg = NULL;
	int chunk_msg_len = sizeof(uint32_t) + chunk_cipherlen + 32 + iv_size;
	chunk_msg = new unsigned char[chunk_msg_len];
	memcpy((void*)chunk_msg, iv, iv_size);
	memcpy((void*)(chunk_msg + iv_size), counter_value, sizeof(uint32_t));
	memcpy((void*)(chunk_msg + iv_size + sizeof(uint32_t)), chunk_ciphertext, chunk_cipherlen);
	memcpy((void*)(chunk_msg + iv_size + sizeof(uint32_t) + chunk_cipherlen), hmac_digest, hmac_digest_len);
	
		//send
	int ret;
	uint16_t chunk_msg_size = chunk_msg_len;
	ret = send_TCP(sock, chunk_msg, chunk_msg_size, key, 16); 
	if(ret != 1){
		cerr << "!!! error in sending file_chunk_msg\n";
		close(sock);
		delete[] chunk_msg;
		return 0;
	}

	delete[] chunk_ciphertext;
	delete[] iv;
	delete[] inbuf;
	delete[] hmac_digest;
	delete[] chunk_msg;

	return 1;
}

int execute_upload(string command, int sock, uint32_t& counter, unsigned char* key){
	
	long int size;
	int ret;
	char* memblock;
	size_t chunk_size = 4096;
	memblock = new char[chunk_size];
	string file_name;


	ret = send_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error send_message()"<<endl;
		return 0;
	}

	while(1){
		cout << endl << "-> Please insert path of the file to be uploaded" << endl;
		getline(cin, file_name);

		if(file_name.length() > 100){
			cout << "file name is too long, max length is 100.\n";
			continue;
		}

			//file name can be long up to 100 
		unsigned char* name_file = new unsigned char[100];
		memset((void*)name_file, 0, 100);
		memcpy(name_file, file_name.data(), file_name.length());

		ifstream file((const char*)name_file, ios::in|ios::binary|ios::ate);

		if(file.is_open()){
				//retrieving file size
			size = file.tellg();
			
				//user can upload files up to 4GB size
			float sizeGB = (((float)size/1024)/1024)/1024;
			if(sizeGB > 4){
				cout << "-> The file is too big. Max size allowed is 4GB.\n";
				break;
			}

			unsigned char* file_size = new unsigned char[sizeof(int)];
			memset(file_size, 0, sizeof(int));
			*((int*)file_size) = htonl(size);

			//sending msg to server with info of the file to upload:--------------------------------------------

				/*counter|{file_name, file_size}Ksc|HMAC[counter|{file_name, file_size}Ksc]*/ 

			ret = secure_send_msgfileinfo(sock, key, name_file, file_size, counter);	

			if(ret == 0){
				close(sock);
				cerr << " !!! error in secure_send_msgfileinfo.\n";
				return 0;
			}

			cout << endl <<  "-> File info: " << endl;
			cout << "File size: " << size << " bytes" << endl;
			cout << "File size[GB]: " << sizeGB << endl;
			
			//actual file chunk transfering -------------------------------------------------------------------------
			string ack_nak;

			//leggo il file a chunk di 4096 byte alla volta
			size_t num_chunk = ceil((float)size/4096);
			cout << "Number of chunks: " << num_chunk << endl << endl;
			
			for(size_t i = 0; i < num_chunk; ++i){ 
				file.seekg(i*chunk_size, ios::beg);	
				int remaining = size - i*4096;
				int byte_to_read = min(4096, remaining);
				file.read(memblock, byte_to_read);

				//cout << "-> Sending File chunk nr[" << i << "]...\n";
				ret = secure_send_msgfilechunk(sock, memblock, byte_to_read, key, counter);

				if(ret == 0){
					close(sock);
					cerr << " !!! error in secure_send_msgfilechunk.\n";
					return 0;
				}		

/*				//wait for ack/nak
				cout << "-> Chunk nr[" << i << "] sent. Waiting for ack..." << endl;
				ret = receive_message(ack_nak, sock, counter, key);
				if(ret == 0){
					cerr<<"Error receive_message ack_nak()"<<endl;
					return 0;
				}

				while(ack_nak.compare("chunk not ok") == 0){
					cout << "-> NAK nr[" << i << "] received" << endl;
					cout << "-> Resenging chunk nr[" << i << "]...\n" << endl;
						//resend chunk
					ret = secure_send_msgfilechunk(sock, memblock, byte_to_read, key, counter);
					if(ret == 0){
						close(sock);
						cerr << " !!! error in secure_send_msgfilechunk.\n";
						return 0;
					}
				}

				cout << "-> ACK nr[" << i << "] received\n" << endl;
*/
			}

				file.close();
				delete[] memblock;
				delete[] name_file;
				return 1;
					
		}
		else
			cout << "unable to read the file." << endl;

	}

	return 1;
	
}

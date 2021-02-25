#include "download.h"

int secure_recv_msgfileinfo(int sock, unsigned char* key, int key_size,
 									uint32_t& counter_server, unsigned char*& msg_fileinfo){

		//init buffer for msg to be received
	unsigned char* msg = NULL;
	uint16_t msg_size = 0;

	//receive msg
		/* iv| counter | {file_name, file_size}Ksc | HMAC[iv|counter|{file_name, file_size}Ksc] */
	int ret;
	ret = receive_TCP(sock, msg, msg_size, key, key_size);
	if(ret == 0){
		cerr << " !!! error in recv counter|{file_name, file_size}Ksc|HMAC[counter|{file_name, file_size}Ksc]\n";
		return 0;
	}

	//msg HMAC_check
		//retrieve iv|counter|{file_name, file_size}Ksc
	bool success;
	int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
	int msg_ciphertext_len = msg_size - sizeof(uint32_t) - 32 - iv_size;

	unsigned char* inbuf = NULL;
	int inbuf_len = sizeof(uint32_t) + msg_ciphertext_len + iv_size;
	inbuf = new unsigned char[inbuf_len];
	memcpy((void*)inbuf, msg, inbuf_len);

		//retrieve HMAC[iv|counter|{file_name, file_size}Ksc]
	unsigned char* received_digest = NULL;
	received_digest = new unsigned char[32];
	memcpy((void*)received_digest, (msg + iv_size + sizeof(uint32_t) + msg_ciphertext_len), 32);

	success = HMAC_check(received_digest, key, key_size, inbuf, inbuf_len);
	if(!success){
		cerr << " !!! error in HMAC_check of msg message" << endl;
		delete[] inbuf;
		delete[] received_digest;
		return 0;
	}

		//get counter received from client
	int counter_value_len = sizeof(uint32_t);
	unsigned char* counter_received = NULL;
	counter_received = new unsigned char[counter_value_len];
	memcpy((void*)counter_received, (msg + iv_size), counter_value_len);

	uint32_t counter_received_ui = ntohl(*((int*)counter_received));

		//check counter received from client
	if(counter_incr_then_check(counter_server, counter_received_ui)==0){
		cout << "!!! incorrect counter value received from client\n";	
		//send msg to resend file_info
			//...
		delete[] counter_received;
		return 0;
	}

		//retrieve iv
	unsigned char* iv = NULL;
	iv = new unsigned char[iv_size];
	memcpy((void*)iv, msg, iv_size);

	//{file_name, file_size}Ksc decryption
		//get {file_name, file_size}Ksc from msg received
	
	unsigned char* msg_ciphertext = NULL;
 	msg_ciphertext = new unsigned char[msg_ciphertext_len];
	memcpy((void*)msg_ciphertext, msg + iv_size + sizeof(uint32_t), msg_ciphertext_len);

		//buffer allocation for the decrypted text
	int msg_plaintext_len;
	unsigned char* msg_plaintext = NULL;
 	msg_plaintext = new unsigned char[msg_ciphertext_len];
	
	success = symmetric_decryption(msg_ciphertext, msg_ciphertext_len, key, iv,
															 msg_plaintext, msg_plaintext_len);
	if(!success){
		cerr << " !!! error in symmetric_decryption of file_info message\n";
		delete[] msg_plaintext;
		return 0;
	}

	memcpy((void*)msg_fileinfo, msg_plaintext, msg_plaintext_len);

	delete[] iv;
	delete[] msg_plaintext;
	delete[] msg_ciphertext;
	delete[] counter_received;
	delete[] received_digest;
	delete[] inbuf;

	return 1;
}

int secure_recv_msgfilechunk(int sock, int chunk_number, unsigned char* key, 
								uint32_t& counter_server, unsigned char*& decrypted_chunk_out){

		//receive i-chunk: <iv | counter | {file_chunk}Ksc | HMAC[iv | counter | {file_chunk}Ksc]>
		
		int iv_size = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
		unsigned char* chunk_msg = NULL;
		uint16_t chunk_msg_size = 0; 
	
		int ret;
		ret = receive_TCP(sock, chunk_msg, chunk_msg_size, key, 16);
		if(ret != 1){
			cerr << " !!! error in recv chunk n. " << chunk_number << endl;
			return 0;
		}

		//msg HMAC_check
			//retrieve iv|counter|{file_chunk}Ksc
		unsigned char* inbuf = NULL;
		int chunk_ciphertext_len = chunk_msg_size - sizeof(uint32_t) - 32 - iv_size; 
		int inbuf_len = sizeof(uint32_t) + chunk_ciphertext_len + iv_size;
		inbuf = new unsigned char[inbuf_len];
		memcpy((void*)inbuf, chunk_msg, iv_size);
		memcpy((void*)(inbuf + iv_size), (chunk_msg + iv_size), sizeof(uint32_t));
		memcpy((void*)(inbuf + sizeof(uint32_t) + iv_size), (chunk_msg + sizeof(uint32_t) + iv_size), chunk_ciphertext_len);

		
			//retrieve HMAC[iv | counter | {file_chunk}Ksc]
		unsigned char* received_digest = NULL;
		int received_digest_len = 32;
		received_digest = new unsigned char[received_digest_len];
		memcpy((void*)received_digest, (chunk_msg + iv_size + sizeof(uint32_t) + chunk_ciphertext_len), 32);

		// 	//simulo chunk corrotto
		// if(chunk_number == 10){
		// 	memcpy((void*)received_digest, chunk_msg, 20);
		// }

		ret = HMAC_check(received_digest, key, 16, inbuf, inbuf_len);
		
		if(!ret){
			cerr << " !!! error in HMAC_check of chunk_msg n. " << chunk_number << endl;
			counter_server++;
			delete[] inbuf;
			delete[] received_digest;
			return -2;
		}

			//retrieve iv
		unsigned char* iv = new unsigned char[iv_size];
		memcpy((void*)iv, chunk_msg, iv_size);

			//get counter received from client	
		unsigned char* counter_received = NULL;
		counter_received = new unsigned char[sizeof(uint32_t)];
		memcpy((void*)counter_received, (chunk_msg + iv_size), sizeof(uint32_t));

		uint32_t counter_received_ui = ntohl(*((int*)counter_received));

			//check counter received from client
		if(!counter_incr_then_check(counter_server, counter_received_ui)){
			cout << "!!! incorrect counter value received from clientn\n";	
			//send msg to resend file_chunk
				//...
			delete[] counter_received;
			return 0;
		}

			//{file_chunk}Ksc decryption
		unsigned char* chunk_ciphertext = NULL;
		chunk_ciphertext = new unsigned char[chunk_ciphertext_len];
		memcpy((void*)chunk_ciphertext, (chunk_msg + iv_size + sizeof(uint32_t)), chunk_ciphertext_len);

			//buffer allocation for chunk_plaintext
		unsigned char* chunk_plaintext = NULL;
		chunk_plaintext = new unsigned char[chunk_ciphertext_len];

		int chunk_plaintext_len;
		ret = symmetric_decryption(chunk_ciphertext, chunk_ciphertext_len, key, 
											iv, chunk_plaintext, chunk_plaintext_len);

		if(!ret){
			cerr << " !!! error in symmetric_decryption of file_chunk message nr " << chunk_number << endl;
			delete[] chunk_ciphertext;
			delete[] chunk_plaintext;
			return 0;
		}

		memcpy((void*)decrypted_chunk_out, chunk_plaintext, chunk_plaintext_len);

		delete[] inbuf;
		delete[] received_digest;
		delete[] counter_received;
		delete[] chunk_ciphertext;
		delete[] chunk_plaintext;

		return 1;
			
}

int execute_download(string command, int sock, uint32_t& counter, unsigned char* key){

	int ret;

	ret = send_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error send_message()"<<endl;
		return 0;
	}

	string filename;
	while(1){
		cout<<"Insert name of file to download"<<endl;
		getline(cin, filename);

		if(filename.length() > 100){
			cout << "file name is too long, max length is 100.\n";
			continue;
		}

		if(filename.find("/") != string::npos){
			cout<<"name format not accepted"<<endl;
			continue;
		}

		break;
	}

	ret = send_message(filename, sock, counter, key);
	if(ret == 0){
		cerr<<"Error send_message()"<<endl;
		return 0;
	}
		
	string file_exists;
	ret = receive_message(file_exists, sock, counter, key);
	if(ret == 0){
		cout << "-> Problem in receiving file name" << endl;
		cerr<<"Error receive_message()"<<endl;
		return 0;
	}

	if(file_exists.compare("The file " + filename + " does not exist.\n") == 0){
		cout << endl << "-> The file [" + filename + "] you asked for does not exist.\n" << endl;
		return 1;
	}

	if(file_exists.compare("Sending file") == 0){
		cout << "-> Receiving file [" + filename + "] ..."  << endl;
	}

	//receive file
		//allocating buffer for file_info message  
	unsigned char* msg_fileinfo = NULL;
	msg_fileinfo = new unsigned char[104];
	memset((void*)msg_fileinfo, 0, 104);

	ret = secure_recv_msgfileinfo(sock, key, 16, counter, msg_fileinfo);
	if(ret == 0){
		cerr << " !!! error in secure_recv_msgfileinfo.\n";
		return 0;
	}


	string bn = string(basename((char*)msg_fileinfo));
	size_t bn_size = bn.length();
	bn.resize(bn_size);

	cout << endl << "File name: " << bn << endl;


		//printing file info
	cout << endl << "-> File info: " << endl;
	cout << "File size: " << htonl(*((int*)(msg_fileinfo+100))) << "bytes" << endl;


	//Actual file chunks receiving----------------------------------------------------------

	string ack;
	string nak; 

	int file_size = htonl(*((int*)(msg_fileinfo+100)));

		//number of file chunk expected
	unsigned int num_chunks = ceil((float) file_size/4096);
	cout << "Number of chunks: " << num_chunks << endl << endl;

		//opening file on disk
	ofstream file(bn, ios::out|ios::binary);
	if(!file.is_open()){
		cerr << "error opening file\n";
	}

	unsigned char* decrypted_chunk = NULL;
	decrypted_chunk = new unsigned char[4096];

	for(unsigned int i = 0; i < num_chunks; ++i){
		
		//receive i-chunk: <counter | {file_chunk}Ksc | HMAC[counter | {file_chunk}Ksc]>

		ret = secure_recv_msgfilechunk(sock, i, key, counter, decrypted_chunk);

		if(ret == 0){
			cerr << " !!! error in secure_recv_msgfilechunk nr " << i << endl;
			return 0;
		}

			//corrupted chunk HMAC_check fail
		bool flag = true;
		while(ret == -2){
			flag = false;
			cerr << "!!! chunk nr [" << i << "] corrupted !!! \n";

				//send nak
			nak = "chunk not ok";
			cout << "-> sending nak nr[" << i << "]...\n" << endl;
			ret = send_message(nak, sock, counter, key);
			if(ret == 0){
				cerr<<"Error send_message() nak"<<endl;
				return 0;
			}
				//wait for resend corrupted chunk
			ret = secure_recv_msgfilechunk(sock, i, key, counter, decrypted_chunk);
			if(ret == 0){
				cerr << " !!! error in secure_recv_msgfilechunk nr " << i << endl;
				return 0;
			}
		
		}

/*		if(flag){
				//else send ack	
			cout << "-> Chunk nr[" << i << "] correctly received.\n";
			cout << "-> Sending ACK nr[" << i << "]...\n\n";
			ack = "chunk ok";
			send_message(ack, sock, counter, key);
			if(ret == 0){
				cerr<<"Error send_message() ack"<<endl;
				return 0;
			}
		}
*/

		//cout << "-> File chunk nr " << i << " correctly received.\n"; 

			//copying chunk on disk
		file.seekp(i*4096, ios::beg);
		int remaining = file_size - i*4096;
		size_t byte_to_write = min(4096, remaining);
		file.write((const char*)decrypted_chunk, byte_to_write);

		
	}

	cout << "-> file [" << bn << "] correctly received.\n" << endl;

	delete[] decrypted_chunk;
	delete[] msg_fileinfo;

	return 1;

}

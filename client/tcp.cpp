#include "tcp.h"
#include "pubkey_enc.h"
#include "symkey_enc.h"

int send_TCP(int sock, unsigned char*& buff, uint16_t buff_size, unsigned char* key, int keylen){

	int mac_size = 32, ret;

	//sending message length
	buff_size = htons(buff_size);
	unsigned char* length = NULL;
	int length_size = 0;

	if(key != NULL){ // a symmetric key has been established
		
		length_size = sizeof(uint16_t) + mac_size;
		length = new unsigned char[length_size];
		int mac_len;

		unsigned char* buff_size_mac = new unsigned char[mac_size];

		ret = HMAC(key, keylen, (unsigned char*)&buff_size, sizeof(uint16_t), buff_size_mac, mac_len);
		if(ret == 0){
			cerr << " !!! error HMAC()" << endl;
			delete[] buff_size_mac;
			return 0;
		}

		memcpy(length, (const void*)&buff_size, sizeof(uint16_t));
		memcpy(length + sizeof(uint16_t), buff_size_mac, mac_len);

	}else{ // key establishment protocol

		length_size = sizeof(uint16_t);
		length = new unsigned char[length_size];
		memcpy(length, (const void*)&buff_size, sizeof(uint16_t));

	}

	ret = send(sock, (void*)length, length_size, 0);
	if(ret == -1){
		perror(" !!! Length send()");
		delete[] length;
		return 0;	
	}			
	if(ret != length_size){
		cout<<" !!! Warning: sent "<<ret<<" bytes instead of "<<length_size<<endl;
		delete[] length;
		return 0;
	}

	//sending actual message
	buff_size = ntohs(buff_size);
	ret = send(sock, (void*)buff, buff_size, 0);
	if(ret == -1){
		perror(" !!! send()");
		delete[] length;
		return 0;	
	}			
	if(ret != buff_size){
		cout<<" !!! Warning: sent "<<ret<<" bytes instead of "<<buff_size<<endl;
		delete[] length;
		return 0;
	}
	delete[] length;
	return 1;	
}

int receive_TCP(int sock, unsigned char*& buff, uint16_t& buff_size, unsigned char* key, int keylen){

	int length_size, ret, mac_size = 32;

	if(key != NULL) // symmetric key established
		length_size = sizeof(uint16_t) + mac_size;
	else 	// key establishment protocol
		length_size = sizeof(uint16_t);
		
	unsigned char* length = new unsigned char[length_size];

	// Acknowledging server's msg length 
	ret = recv(sock, (void*)length, length_size, MSG_WAITALL);
	if(ret == 0){
		cout<<"-> Server closed the connection. Closing sock."<<endl;
		return 0;	
	}		
	if(ret == -1){
		perror(" !!! Length recv()");
		return 0;
	}
	if(ret != length_size){
		cout<<" !!! Warning: received "<<ret<<" bytes instead of "<<length_size<<endl;
		return 0;
	}

	if(key != NULL){
		//mac validation
		unsigned char* hashed = new unsigned char[mac_size];
		memcpy(hashed, length + sizeof(uint16_t), mac_size);

		int inbuf_len = sizeof(uint16_t);
		unsigned char* inbuf = new unsigned char[inbuf_len];
		memcpy(inbuf, length, inbuf_len);

		ret = HMAC_check(hashed, key, keylen, inbuf, inbuf_len);
		if(ret == 0){
			cerr<<"Error HMAC_check()"<<endl;
			return 0;
		}

		memcpy((char*)&buff_size, length, sizeof(uint16_t));

	}else{
		memcpy((char*)&buff_size, length, sizeof(uint16_t));
	}

	buff_size = ntohs(buff_size);

	// Receving actual msg
	buff = new unsigned char[buff_size];
	ret = recv(sock, (void*)buff, buff_size, MSG_WAITALL);
	if(ret == -1){
		perror(" !!! recv()");
		return 0;	
	}			
	if(ret != buff_size){
		cerr<<" !!! Warning: received "<<ret<<" bytes instead of "<<buff_size<<endl;
		return 0;
	}
	return 1;	
}

int receive_cert_nonce(int sock, X509** server_cert, unsigned char** server_nonce){

	unsigned char* cert_buf = NULL;
	unsigned char* nonce_buf = NULL;
	uint16_t buff_size = 0;
	uint16_t nonce_size = 0;	
	int ret;

	ret = receive_TCP(sock, cert_buf, buff_size, NULL, 0);
	if(ret == 0){
		return 0;
	}

	X509* s_cert = d2i_X509(NULL, (const unsigned char**)&cert_buf, buff_size);
	if(s_cert == NULL){
		cerr<<" !!! Error: s_cert is NULL"<<endl;
		return 0;
	}

	cout<<"-> M2 : Server's certificate received!"<<endl;
	*server_cert = s_cert;

	ret = receive_TCP(sock, nonce_buf, nonce_size, NULL, 0);
	if(ret == 0){
		return 0;
	}

	cout<<"-> M2 : Server's nonce received!"<<endl;
	*server_nonce = nonce_buf;
	return 1;
}

int send_cert_nonce(int sock, unsigned char* client_nonce){

	uint16_t buff_size;	
	int ret;
	unsigned char* cert_buf = NULL;

	X509* mycert = import_cert("client_cert.pem");	
	if(mycert == NULL) return 0;
	
	buff_size = i2d_X509(mycert, &cert_buf);
	if(buff_size < 0) {
		cerr<<" !!! Error: buff_size not valid"<<endl;
		return 0;
	}

	ret = send_TCP(sock, cert_buf, buff_size, NULL, 0);
	if(ret == 0){
		return 0;
	}

	cout<<"-> M1 : Client certificate sent!"<<endl;
	free(cert_buf);

	ret = send_TCP(sock, client_nonce, sizeof(uint32_t), NULL, 0);
	if(ret == 0){
		return 0;
	}
	cout<<"-> M1 : Client nonce sent!"<<endl;

	return 1;
}
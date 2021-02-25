#include "pubkey_enc.cpp"
#include "tcp.cpp"
#include "session.cpp"
#include "list_file.cpp"
#include "symkey_enc.cpp"
#include "upload.cpp"
#include "download.cpp"
#include "quit.cpp"
#include "include.h"

int main(int argc, char* argv[]){
	
	if(argc != 2){
		cout<<" !!! Error: incorrect number of arguments. \nCorrect sintax : ./server <listening_TCP_port>"<<endl;
		return 0;	
	}
	cout<<" - Server starting..."<<endl;

	

		/* initialization for TCP communication */
		int connection_sock;
		struct sockaddr_in sv_addr, cl_addr;	
		socklen_t cl_len;	

		memset(&sv_addr, 0, sizeof(sv_addr));
		sv_addr.sin_family = AF_INET;
		sv_addr.sin_port = htons(atoi(argv[1]));
		sv_addr.sin_addr.s_addr = INADDR_ANY;

		cout<<" - Creating TCP socket..."<<endl;
		if(	(connection_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
			perror(" !!! socket() ");
			return 0;	
		} 

		cout<<" - Binding socket to "<< argv[1]<<" port on all local interfaces..."<<endl;
		if( bind(connection_sock, (struct sockaddr*)&sv_addr, sizeof(sv_addr)) == -1 ){		
			perror(" !!! bind() ");
			close(connection_sock);
			return 0;		
		}

		if( listen(connection_sock, 1) == -1 ){
			perror(" !!! listen() ");
			close(connection_sock);
			return 0;		
		} 
		cout<<" - Server listening on socket"<<endl;
		
	while(1){
		int client_sock;
		cl_len = sizeof(cl_addr);
			memset(&cl_addr, 0, cl_len);
			
		cout<<"--- Server ready to accept a connection request ---"<<endl;
		if( (client_sock = accept(connection_sock, (struct sockaddr*)&cl_addr, &cl_len)) == -1 ){
			perror(" !!! accept() ");
			close(connection_sock);
			return 0;
		}
		cout<<"-> A client is connected!"<<endl;

		/* initialization for public-key encryption */
		int ret;
		vector<string> valid_subject_names;
		EVP_PKEY* prvkey = NULL;
		X509* CA_cert = NULL;
		X509_CRL* CA_crl = NULL;
		X509_STORE* store = NULL;
		X509* client_cert = NULL;
		EVP_PKEY* client_pubkey = NULL;
		unsigned char* server_nonce = NULL;
		unsigned char* client_nonce = NULL;

		OpenSSL_add_all_algorithms();
		import_valid_subject_names("trusted_subject_names.txt", valid_subject_names);

		ret = init_public_key_enc(prvkey, CA_cert, CA_crl, store, valid_subject_names);
		if(ret == 0) return 0;

		EVP_cleanup();


		cout<< "-> Starting certificate exchange protocol"<<endl<<endl;

		/* M1 = C -> S : <Cc, Nc> */
		cout<<endl;
		cout<< "-> M1 : Receiving client's certificate and nonce..."<<endl;

		ret = receive_cert_nonce(client_sock, &client_cert, &client_nonce);
		if(ret == 0) {
			close(client_sock);
			close(connection_sock);
			return 0;
		}

		ret = verify_cert(store, client_cert);
		if(ret == 0) {
			cerr<<" !!! M1 : Client's certificate is invalid"<<endl;
			close(client_sock);
			close(connection_sock);
			return 0;
		}
		cout<<"-> M1 : Client's certificate is valid"<<endl;

			/* storing client's public key */
		client_pubkey = X509_get_pubkey(client_cert);
		if(client_pubkey == NULL){
			cerr<<" !!! M1 : Client's public key is NULL"<<endl;
			close(client_sock);
			close(connection_sock);
			return 0;
		}
		cout<<"-> M1 : Client's public key stored correctly"<<endl;

		/* M2 = S -> C : <Cs, Ns> */
		cout<<endl;
		cout<<"-> M2 : Sending server's certificate and nonce"<<endl;

		/*generating a pseudo-random byte as nonce */
		server_nonce = new unsigned char[sizeof(uint32_t)];
		ret = generate_fresh_nonce(server_nonce);
		if(ret == 0){
			delete[] server_nonce;
			return 0;
		}
		
		ret = send_cert_nonce(client_sock, server_nonce);
		if(ret == 0) {
			close(client_sock);
			close(connection_sock);
			return 0;
		}

		/* M3 = C -> S : <DS_Ns> */
		cout<<endl;
			/* receive nonce's signature */
		unsigned char* signed_nonce = NULL;
		uint16_t signed_nonce_size = 0;
		ret = receive_TCP(client_sock, signed_nonce, signed_nonce_size, NULL, 0);
		if(ret == 0){
			close(client_sock);
			close(connection_sock);
			return 0;
		}

		verify_nonce_signature(server_nonce, signed_nonce, client_pubkey);
		cout<<"-> M3 : Nonce's digital signature authentication successful"<<endl;

		/*  M4 = S -> C : <(Nc, {Ksc}kpubC), DS_NcKsc>  */
		cout<<endl;
			/* generating random 128bit session key Ksc */
	    unsigned char* Ksc = new unsigned char[16];
	    ret = generate_symmetric_key(Ksc);
	    if(ret == 0){
	    	close(client_sock);
	    	close(connection_sock);
	    	delete[] Ksc;
			return 0;
	    }

	    	/* encypting Ksc with client's public key(digital envelope) */
	    unsigned char* ciphertext = NULL;
	    int cipherlen = 0;
	    unsigned char* encrypted_ksym = NULL;
	    int encrypted_ksym_len = 0;
	    unsigned char* iv = NULL;
	    int iv_size = 16;
	    ret = build_digital_envelope(client_pubkey, Ksc, ciphertext, cipherlen, encrypted_ksym, encrypted_ksym_len, iv);
		if(ret == 0){
	    	close(client_sock);
	    	close(connection_sock);
	    	delete[] Ksc;
			return 0;
	    }

	    	/* digital envelope construction */
	    unsigned char* digital_env = new unsigned char[encrypted_ksym_len + cipherlen];
	    memcpy((void*)digital_env, ciphertext, cipherlen);
	    memcpy((void*)(digital_env + cipherlen), encrypted_ksym, encrypted_ksym_len);
	    int digital_env_len = cipherlen + encrypted_ksym_len ; // 32 + 256 

	    	/* msg4 construction */
		unsigned char* msg4 =  new unsigned char[sizeof(uint32_t) + digital_env_len + iv_size];// nonceC + digital_env + iv
		memcpy((void*)msg4, client_nonce, sizeof(uint32_t));
		memcpy((void*)(msg4 + sizeof(uint32_t)), digital_env, digital_env_len);
		memcpy((void*)(msg4 + sizeof(uint32_t) + digital_env_len), iv, iv_size);
		uint16_t msg4_size = sizeof(uint32_t) + digital_env_len + iv_size;

			/* sending digitally signed msg4 to client */
		ret = send_ds_m4(prvkey, msg4, msg4_size, client_sock);
		if(ret == 0){
			cout<<"-> M4 : Error sending symmetric key and client nonce"<<endl;
	    	close(client_sock);
	    	close(connection_sock);
	    	delete[] Ksc;
			return 0;
	    }
	    cout<<"-> M4 : Digitally signed symmetric key and client nonce sent"<<endl;

		//-------------Inizio parte operativa ------------//
	    cout<<endl;

	    cout << "//---------------------------- Ready ----------------------------//" << endl << endl;

			/*init counter againist replay*/
		uint32_t counter = 0;
		string command;

		while(1){
			cout<<"-> Waiting for command ------------------------:"<<endl;
			ret = receive_message(command, client_sock, counter, Ksc);
			if(ret == 0){
				cout<<"Error receive_message()"<<endl;
				cout << "\n!!! ----------------------- Probable Attack  ----------------------- !!!\n";
				cout << "\n-> Restarting session................................................\n\n\n";
				break;	
			}
			if(ret == -1){
				break;
			}

			cout<<"-> Executing command : "<<command<<endl;

			ret = execute_command(command, client_sock, counter, Ksc);
			if(ret == 0){
				cout<<"Command cannot be executed"<<endl;
				continue;
			}
				//client asked for download of an unexisting file
			if(ret == 2){
				continue;
			}
				//HMAC_CHECK failed, corrupted chunk
			if(ret == -2){
				cout << "\n!!! ----------------------- Probable Attack  ----------------------- !!!\n";
				cout << "\n-> Restarting session................................................\n\n\n";
				break;	
			}

			if(ret == -1){
				break;
			}
		}
		
		close(client_sock);
		delete[] Ksc;
		delete[] digital_env;
		delete[] msg4;

	}

//	close(client_sock);
//	close(connection_sock);
//	delete[] nonce_client;
//  delete[] Ksc;
	return 0;
}

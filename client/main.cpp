#include "pubkey_enc.cpp"
#include "tcp.cpp"
#include "session.cpp"
#include "symkey_enc.cpp"
#include "list_file.cpp"
#include "upload.cpp"
#include "download.cpp"
#include "quit.cpp"
#include "include.h"

int main(int argc, char *argv[]){

	if(argc != 3){
		cout<<" !!! Error: incorrect number of arguments. \nCorrect sintax : ./client <server_IP> <server_TCP_port>"<<endl<<endl;
		return 0;	
	}	

	/* initialization for public-key encryption */
	int ret;
	vector<string> valid_subject_names;
	EVP_PKEY* prvkey = NULL;
	X509* CA_cert = NULL;
	X509_CRL* CA_crl = NULL;
	X509_STORE* store = NULL;
	X509* server_cert = NULL;
	EVP_PKEY* server_pubkey = NULL;
	unsigned char* server_nonce = NULL;
	unsigned char* client_nonce = NULL;

	OpenSSL_add_all_algorithms();
	import_valid_subject_names("trusted_subject_names.txt", valid_subject_names);

	ret = init_public_key_enc(prvkey, CA_cert, CA_crl, store, valid_subject_names);
	if(ret == 0) return 0;

	EVP_cleanup();

	/* inizialization of TCP connection with the server */
	int TCP_sock;
	struct sockaddr_in sv_addr;
	
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &sv_addr.sin_addr);

	if( (TCP_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
		perror("!!! TCP socket() ");
		return 0;	
	} 
	
	if( (ret = connect(TCP_sock, (struct sockaddr*)&sv_addr, sizeof(sv_addr))) == -1 ){
		perror("!!! connect() ");
		close(TCP_sock);
		return 0;
	}
	cout<<"\nConnection to server on IP "<< argv[1] <<" , port "<< argv[2] <<" successful!\n"<<endl;
	
	cout<< "-> Starting certificate exchange protocol"<<endl;
	
	/* M1 = C -> S : <Cc, Nc> */
	cout<<endl;
	cout<< "-> M1 : Sending client's certificate and nonce..."<<endl;

		/*generating a pseudo-random byte as nonce */
	client_nonce = new unsigned char[sizeof(uint32_t)];
	ret = generate_fresh_nonce(client_nonce);
	if(ret == 0){
		delete[] client_nonce;
		return 0;
	}

	ret = send_cert_nonce(TCP_sock, client_nonce);
	if(ret == 0) {
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}

	/* M2 = S -> C : <Cs, Ns> */
	cout<<endl;
	cout<< "-> M2 : Receiving server certificate and nonce..."<<endl;

	ret = receive_cert_nonce(TCP_sock, &server_cert, &server_nonce);
	if(ret == 0) {
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}

	ret = verify_cert(store, server_cert);
	if(ret == 0) {
		cerr<<" !!! M2 : Server's certificate is invalid"<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}
	cout<<"-> M2 : Server's certificate is valid"<<endl;

		/* storing server's public key */
	server_pubkey = X509_get_pubkey(server_cert);
	if(server_pubkey == NULL){
		cerr<<" !!! M2 : Server's public key is NULL"<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}
	cout<<"-> M2 : Server's public key stored correctly"<<endl;

	/*  M3 = C -> S : <DS_Ns>  */

	send_ds_nonce(prvkey, server_nonce, TCP_sock);
	if(ret == 0){
		cerr<<" !!! M3 : Cannot send signed server nonce"<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}

	cout<<"-> M3 : Signed server nonce sent!"<<endl;

	/* M4 = S -> C : <msg4,  DS_msg4> */
	cout<<endl;
		/* msg4 = nonce_client | {Ksc}k | {K}pubC | iv */
	unsigned char* msg4 = NULL;
	uint16_t msg4_size = 0;
	ret = receive_TCP(TCP_sock, msg4, msg4_size, NULL, 0);
	if(ret == 0){
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}

	// signature verification
	ret = verify_signature(msg4, msg4_size, server_pubkey);
	if(ret == 0){
		cerr<<" !!! M4 : Signature authentication error "<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		return 0;
	}
	cout<<"-> M4 : Digital signature authentication successful"<<endl;

	// decrypting 128-bit symmetric key
	int ksc_size = 16;
	unsigned char* Ksc = new unsigned char[ksc_size];
	ret = get_symmetric_key(msg4, prvkey, Ksc);
	if(ret == 0){
		cerr<<" !!! M4 : Can't retrieve symmetric key "<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		delete[] Ksc;
		return 0;
	}
	cout<<"-> M4 : Symmetric Key retrieved"<<endl;

	unsigned char* c_nonce = new unsigned char[sizeof(uint32_t)];
	memcpy(c_nonce, msg4, sizeof(uint32_t));
	ret = CRYPTO_memcmp(c_nonce, client_nonce, sizeof(uint32_t));
	if(ret != 0){
		cerr<<" !!! M4 : client nonces are not equal "<<endl;
		close(TCP_sock);
		delete[] client_nonce;
		delete[] c_nonce;
		delete[] Ksc;
		return 0;
	}

	cout<<"-> M4 : Client nonce retieved"<<endl;
	delete[] c_nonce;

	//------------------Inizio parte operativa------------------//

	cout<<endl;

	cout << "//---------------------------- Ready ----------------------------//" << endl << endl;

		/*init counter againist replay*/
	uint32_t counter = 0;

	string command;
	while(1){
		cout<<"-> Insert command ------------------------:"<<endl;
		getline(cin, command);
		ret = is_command_valid(command);
		if(ret == 0){
			cout<<"Command is not valid. Try again"<<endl;
			continue;
		}

		ret = execute_command(command, TCP_sock, counter, Ksc);
		if(ret == 0){
			cout<<"-> Command cannot be executed"<<endl;
			close(TCP_sock);
			delete[] client_nonce;
			delete[] Ksc;
			return 0;
		}
		if(ret == -1){
			break;
		}
	}

	close(TCP_sock);
	delete[] client_nonce;
	delete[] Ksc;
	return 0;

}
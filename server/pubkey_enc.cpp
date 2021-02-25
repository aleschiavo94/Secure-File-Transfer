#include "tcp.h"
#include "pubkey_enc.h"

void import_valid_subject_names(const char* filename, vector<string> &names){
	ifstream in(filename, ifstream::in);
	string name;
	while (getline(in, name)){
		if(name.size() > 1)
			names.push_back(name);
	}
	in.close();
}

string get_subject_name(X509* cert){
	X509_NAME* subject_name = X509_get_subject_name(cert);
	string name = X509_NAME_oneline(subject_name, NULL, 0);
	return name;
}

int verify_subject_name(X509* cert, vector<string> valid_subject_names){

	vector<string>::iterator it;
	string name;

	name = get_subject_name(cert);
	/* comparing it to trusted subject names; */
	
	it = find (valid_subject_names.begin(), valid_subject_names.end(), name);
	if (it != valid_subject_names.end()){
    	cout << "-> Subject name found in trusted subject names' file : " << *it << endl;
    	return 1;
	}
  	else{
    	cerr << " !!! Subject name not found in trusted subject names' file" <<endl;
    	return 0;
  	}
}

X509* import_cert(const char* filename){
	X509* cert;
	FILE* file = fopen(filename, "r");
	if(!file){
		cerr<<" !!! Cannot open "<<filename<<" file"<<endl;
		return NULL;
	}
	cert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!cert){
		cerr<<" !!! Cannot read certificate from PEM file"<<endl;
		return NULL;
	}
	fclose(file);

	return cert;
}

void import_old_nonces(const char* filename, vector<string> &old_nonces){
	ifstream in(filename, ifstream::in);
	string old_nonce;
	while (getline(in, old_nonce)){
		if(old_nonce.size() > 1)
			old_nonces.push_back(old_nonce);
	}
	in.close();
}

EVP_PKEY* import_RSA_PKEY(const char* filename){
	EVP_PKEY* prvkey;
	FILE* file = fopen(filename, "r");
	if(!file){
		cerr<<" !!! Cannot open "<<filename<<" file"<<endl;
		return NULL;
	}
	prvkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!prvkey){
		cerr<<" !!! Cannot read private key from file"<<endl;
		return NULL;
	}
	fclose(file);
	cout<<"-> RSA 2048 private key loaded from PEM file"<<endl;
	return prvkey;
}

X509_CRL* import_crl(const char* filename){
	X509_CRL* crl;
	FILE* file = fopen(filename, "r");
	if(!file){
		cerr<<" !!! Cannot open "<<filename<<" file"<<endl;
		return NULL;
	}
	crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
	if(!crl){
		cerr<<" !!! Cannot read CRL from file"<<endl;
		return NULL;
	}
	fclose(file);
	cout<<"-> loaded CRL from PEM file"<<endl;
	return crl;
}

X509_STORE* init_store(X509* CA_cert, X509_CRL* crl){
	X509_STORE* store = X509_STORE_new();
	if(store == NULL){
		cerr<<" !!! Error creating the store"<<endl;
		return NULL;
	}

	X509_STORE_add_cert(store, CA_cert);
	X509_STORE_add_crl(store, crl);
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

	return store;
}

int verify_cert(X509_STORE* store, X509* cert){
	int ret = 0;
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, cert, NULL);
	ret = X509_verify_cert(ctx);
	if(ret != 1){
		cerr<<" !!! Certificate authentication failed for " << get_subject_name(cert)<<ret<< endl;
		return 0;
	}
	cout<<"-> M2 : Certificate authentication successful for "<< get_subject_name(cert)<< endl;

	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);

	return 1;
}

int init_public_key_enc(EVP_PKEY* &prvkey, X509* &CA_cert, X509_CRL* &CA_crl, X509_STORE* &store, 
	vector<string> valid_subject_names)
{
	// importing private key from PEM file, CA generated
	prvkey = import_RSA_PKEY("server_key.pem");
	if(prvkey == NULL) return 0;

	// importing CA's certificate
	CA_cert = import_cert("Cybersecurity_CA_cert.pem");
	if(CA_cert == NULL) return 0;

	if(!verify_subject_name(CA_cert, valid_subject_names)){
		cerr<<" !!! Error validating subject name"<<endl;
		return 0;
	}

	// importing CA's CRL
	CA_crl = import_crl("Cybersecurity_CA_crl.pem");
	if(CA_crl == NULL) return 0;

	// adding CA's certificate and CRL to the Store
	store = init_store(CA_cert, CA_crl);
	if(store == NULL) return 0;

	return 1;
}

int generate_fresh_nonce(unsigned char* &out_nonce){
	RAND_poll(); // seeding the PRNG
	
	vector<string> old_nonces;
	import_old_nonces("old_nonces.txt", old_nonces);

	vector<string>::iterator it;
	while(1){

		int ret = RAND_bytes(out_nonce, sizeof(uint32_t));
		if(ret != 1){
			cerr<<" !!! Error generating nonce"<<endl;
			delete[] out_nonce;
			return 0;
		}
		string s_nonce(reinterpret_cast<char*>(out_nonce));

		it = find (old_nonces.begin(), old_nonces.end(), s_nonce);
		if (it == old_nonces.end()){
			//fresh
			ofstream out("old_nonces.txt", ofstream::app);
    		out << out_nonce << endl;
    		out_nonce = out_nonce;
    		out.close();
			break;
		}
	  	else{
	  		//not fresh
	  		delete[] out_nonce;
	  		continue;
	  	}
  	}
	return 1;
}

int generate_symmetric_key(unsigned char*& Ksc){
	
	int ret;

	RAND_poll();
    unsigned char* Ksc_temp = new unsigned char(16);

    ret = RAND_bytes(Ksc_temp, 16);
    if(ret != 1){
			cerr<<" !!! Error generating symmetric key"<<endl;
			delete[] Ksc_temp;	
			return 0;
		}
	Ksc = Ksc_temp;
	delete[] Ksc_temp;
	return 1;
}

int build_digital_envelope(EVP_PKEY* client_pubkey, unsigned char* Ksc, unsigned char*& ciphertext_out, int& cipherlen_out,
	unsigned char*& encrypted_key_out, int& encrypted_key_len_out, unsigned char*& iv_out )
{ 

	int ret;

	int encrypted_key_len;
	unsigned char* encrypted_key = new unsigned char[EVP_PKEY_size(client_pubkey)];
	unsigned char* ciphertext = new unsigned char[16 + 16]; //keylen + padding
	unsigned char* iv = new unsigned char[(EVP_CIPHER_iv_length(EVP_aes_128_cbc()))];
	int outlen, cipherlen;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	  
	ret = EVP_SealInit(ctx, EVP_aes_128_cbc(), &encrypted_key, &encrypted_key_len, iv, &client_pubkey, 1);
	if(ret == 0){
	  cerr << " !!! SealInit error " << endl;
	  delete[] encrypted_key;
	  delete[] ciphertext;
	  delete[] iv;
	  return 0;
	}

	EVP_SealUpdate(ctx, ciphertext, &outlen, Ksc, 16);
	if(ret == 0){
	  cerr << " !!! SealInit error " << endl;
	  delete[] encrypted_key;
	  delete[] ciphertext;
	  delete[] iv;
	  return 0;
	}
	cipherlen = outlen;
	EVP_SealFinal(ctx, ciphertext + cipherlen, &outlen);
	if(ret == 0){
	  cerr << " !!! SealInit error " << endl;
	  delete[] encrypted_key;
	  delete[] ciphertext;
	  delete[] iv;
	  return 0;
	}
    cipherlen += outlen;
	EVP_CIPHER_CTX_free(ctx);

	iv_out = iv;
	ciphertext_out = ciphertext;
	cipherlen_out = cipherlen; 
	encrypted_key_out = encrypted_key;
	encrypted_key_len_out = encrypted_key_len;

	return 1;
}

int send_ds_m4(EVP_PKEY* prvkey, unsigned char* m4_plain, int m4_plain_len, int sock){

	int ret = 0;

	unsigned int m4_signature_len;
	unsigned char* m4_signature = new unsigned char[EVP_PKEY_size(prvkey)];
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	ret = EVP_SignInit(ctx, EVP_sha256());
	if(ret == 0){
		delete[] m4_signature;
		return 0;
	}
	ret = EVP_SignUpdate(ctx, (unsigned char*)m4_plain, m4_plain_len);
	if(ret == 0){
		delete[] m4_signature;
		return 0;
	}
	ret = EVP_SignFinal(ctx, m4_signature, &m4_signature_len, prvkey);
	if(ret == 0){
		delete[] m4_signature;
		return 0;
	}
	
	EVP_MD_CTX_free(ctx);

		/* composition of m4: m4_plain|ds(m4_plain) */
	unsigned char* m4 =  new unsigned char[m4_plain_len + m4_signature_len];
	memcpy((void*)m4, m4_plain, m4_plain_len);
	memcpy((void*)(m4 + m4_plain_len), m4_signature, m4_signature_len);

	uint16_t m4_len = m4_plain_len + m4_signature_len;

	ret = send_TCP(sock, m4, m4_len, NULL, 0); 
	if(ret == 0){
		delete[] m4_signature;
		delete[] m4;
		return 0;
	}

	delete[] m4_signature;
	delete[] m4;
	return 1;
}

int verify_signature(unsigned char* msg, int msg_size, EVP_PKEY* pubkey){

	int ret;
	int signature_len = 256;

	//copying plain message into msg4_plain
	int msg_plain_size = msg_size - signature_len;
	unsigned char* msg_plain = new unsigned char[msg_plain_size];
	memcpy(msg_plain, msg, msg_plain_size);

	//copying signature
	unsigned char* signature = new unsigned char[signature_len];
	memcpy(signature, (msg + msg_size - signature_len ), signature_len);

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	ret = EVP_VerifyInit(ctx, EVP_sha256());
	if(ret != 1){
		delete[] msg_plain;
		delete[] signature;
		return 0;
	}
	ret = EVP_VerifyUpdate(ctx, msg_plain, msg_plain_size);
	if(ret != 1){
		delete[] msg_plain;
		delete[] signature;
		return 0;
	}
	ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
	if(ret != 1){
		delete[] msg_plain;
		delete[] signature;
		return 0;
	}

	EVP_MD_CTX_free(ctx);
	delete[] msg_plain;
	delete[] signature;
	return 1;
}

int verify_nonce_signature(unsigned char* nonce, unsigned char* signed_nonce, EVP_PKEY* pubkey){

	int ret;
	int signature_len = 256;

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	ret = EVP_VerifyInit(ctx, EVP_sha256());
	if(ret != 1){
		return 0;
	}
	ret = EVP_VerifyUpdate(ctx, nonce, sizeof(uint32_t));
	if(ret != 1){
		return 0;
	}
	ret = EVP_VerifyFinal(ctx, signed_nonce, signature_len, pubkey);
	if(ret != 1){
		return 0;
	}

	EVP_MD_CTX_free(ctx);
	return 1;
}
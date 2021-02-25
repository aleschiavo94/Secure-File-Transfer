#include "list_file.h"
#include "session.h"

int execute_list(string command, int sock, uint32_t& counter, unsigned char* key){
	
	int ret;
	ret = send_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error send_message()"<<endl;
		return 0;
	}

	ret = receive_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error receive_message()"<<endl;
		return 0;
	}
	cout<<endl;
	cout<<"-- list of files: --"<<endl;
	cout<<command<<endl;

	return 1;
}
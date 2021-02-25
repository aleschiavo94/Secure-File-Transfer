#include "quit.h"

int execute_quit(string command, int sock, uint32_t& counter, unsigned char* key){
	
	int ret;
	//sending "quit" command
	ret = send_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error send_message()"<<endl;
		return 0;
	}
	//receiving server's ack
	ret = receive_message(command, sock, counter, key);
	if(ret == 0){
		cerr<<"Error receive_message()"<<endl;
		return 0;
	}

	if(command.compare("session closed")!=0){
		cerr<<"Session couldn't be closed gracefully"<<endl;
		return 0;
	}
	cout<<"Session closed correctly ------------------------------------------------------------------\n"<<endl;
	return 1;
}


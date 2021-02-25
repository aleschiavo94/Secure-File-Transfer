#include "quit.h"

int execute_quit(int sock, uint32_t& counter, unsigned char* key){
	
	int ret;

	ret = send_message("session closed", sock, counter, key);
  	if(ret == 0){
    	cerr<<"Error send_message()"<<endl;
    	return 0;
  	}
  	cout<<"Terminating session -------------------------------------------------------------\n"<<endl;
  	return 1;
}
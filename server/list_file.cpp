#include "list_file.h"


int execute_list(int sock, uint32_t& counter, unsigned char* key){
  
  int ret;

  string list = get_file_list();
  if(list.compare("NULL") == 0){
    cerr<<"Error get_file_list()"<<endl;
    return 0;
  } 

  ret = send_message(list, sock, counter, key);
  if(ret == 0){
    cerr<<"Error send_message()"<<endl;
    return 0;
  }

  cout<<"-- list of files: --"<<endl;
  cout<<list<<endl;

  return 1;
}

string get_file_list(){
	
	int ret;

	if (fork() == 0){
    	// child : creating the list file

		int fd;
    	if ((fd = open("list_file.txt", O_WRONLY|O_CREAT|O_TRUNC)) == -1){
    		perror("Cannot open output file\n");
    		return "NULL";
		}

		dup2(fd, 1); // make stdout go to file
		close(fd);   // fd no longer needed - the dup'ed handles are sufficient

		execl( "/bin/ls" , "ls", "files/", (char *) 0 );
		perror("execv fallita");
	}else{
		// parent : reading the list file

		string list = "";
		int status;
		ret = wait(&status);
		if(ret == -1){
			cerr<<" !!! Error waiting child process"<<endl;
			return "NULL"; 	
		}

		ifstream is ("list_file.txt", ifstream::binary);
  		if (is) {
    		// get length of file:
    		is.seekg (0, is.end);
    		int length = is.tellg();
    		is.seekg (0, is.beg);

    		char * buffer = new char [length];

    		// read data as a block:
    		is.read (buffer,length);

    		if (is)
      			cout << "-> list_file.txt read successfully"<<endl;
    		else{
     			cout << " !!! Error: " << is.gcount() << " could be read"<<endl;
     			is.close();
     			return "NULL";
    		}
   		 	
   		 	is.close();
   		 	list = buffer;
    		delete[] buffer;
        list.append("\0");
    		return list;
  		}
  		return "NULL";
  	}
  	return "NULL";
}
#ifndef INCLUDE_H
#define INCLUDE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include <cstring>
#include <cstdio>
#include <string>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <math.h>
#include <limits>

using namespace std;

vector<string> commands = { "list", "upload", "download", "quit" };

#endif
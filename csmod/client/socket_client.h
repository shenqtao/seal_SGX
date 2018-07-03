#ifndef SOCKET_CLIENT
#define SOCKET_CLIENT

#include <stdio.h>  // standard IO
#include <stdlib.h> //standard  libary
#include <string.h>
#include <sys/socket.h>
#include <unistd.h> //unix standard

#include "../socket_config.h"

int socket_connect(const char *ip, int port);
size_t send_to_sgx(int client_fd, command cmd, const char* buffer, unsigned int length);


#endif

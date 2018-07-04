#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include <stdio.h>  // standard IO
#include <stdlib.h> //standard  libary
#include <string.h>
#include <sys/socket.h>
#include <unistd.h> //unix standard

#include "../socket_config.h"

const int bufflen = 20000000; 

int socket_bind(const char *ip, int port);
static void accpet_client(int *clients_fd, int listen_fd);
static void recv_client_msg(int *clients_fd, fd_set *readfds);
static void handle_client_msg(int fd, struct message_head *head, char *buf);

#endif

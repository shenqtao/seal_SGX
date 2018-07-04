//
// Created by sqt on 18-6-29.
//
#include "socket_client.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>  // standard IO
#include <stdlib.h> //standard  libary
#include <string.h>
#include <sys/socket.h>
#include <unistd.h> //unix standard
#include <iostream>
#include <string>


int socket_connect(const char *ip, int port) {
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        perror("create socket filed.");
        exit(1);
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(client_fd, (sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect server filed");
        exit(1);
    }

    printf("connect success\n");
    return client_fd;
}

/**
 * 把命令和数据封装在一�?通过socket发�? * @param client_fd
 * @param cmd
 * @param buffer
 * @param length
 * @return
 */
size_t send_to_sgx(int client_fd, command cmd, const char* buffer, unsigned int length)
{
    struct message_head head;
    head.data_len = length;
    head.cmd = cmd;

    size_t send_size = sizeof(struct message_head) + sizeof(char)*length;
    char *mem = (char *)malloc(send_size);
    if(mem == NULL)
    {
      printf("Out of memory.\n");
      return -1;
    }

    memcpy(mem, &head, sizeof(struct message_head));
    memcpy(mem+sizeof(struct message_head), buffer, length);

    if (send_size != write(client_fd, mem, send_size)) {
        printf("%d %d\n", send_size, send_size);
        perror("send buf error");
    }

    free(mem);
    return send_size;

}

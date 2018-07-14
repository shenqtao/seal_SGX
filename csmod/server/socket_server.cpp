#include "socket_server.h"
#include <iostream>
#include <sys/time.h>
#include <memory.h>
#include <arpa/inet.h>

using namespace std;

int socket_bind(const char *ip, int port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("create socket error");
        exit(1);
    }
    
    int on=1;  
    if((setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)  
    {  
        perror("setsockopt failed");  
        exit(EXIT_FAILURE);  
    }  
    
    sockaddr_in addr;
    memset(&addr, 0, sizeof(sockaddr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind socket error");
        exit(1);
    }

    if (listen(listen_fd, IPC_MAX_CONN) == -1) {
        perror("listen socket error");
        exit(1);
    }
    printf("listen success\n");
    return listen_fd;
}


void accpet_client(int *clients_fd, int listen_fd) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd == -1) {
        printf("accept failed: %s.\n", strerror(errno));
        return;
    } else {
        printf("new client accpeted\n");
    }

    size_t i = 0;
    for (; i < IPC_MAX_CONN; ++i) {
        if (clients_fd[i] == -1) {
            clients_fd[i] = client_fd;
            break;
        }
    }

    if (i == IPC_MAX_CONN) {
        close(client_fd);
        printf("too many clients connectioned \n");
    }
}
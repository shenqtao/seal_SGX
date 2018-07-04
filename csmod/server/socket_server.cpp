#include "../socket_server.h"
#include <iostream>
#include <sys/time.h>
#include <memory.h>
#include <arpa/inet.h>
#include <assert.h>

using namespace std;

int socket_bind(const char *ip, int port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("create socket error");
        exit(1);
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


static void accpet_client(int *clients_fd, int listen_fd) {
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

/**
 * 通过select查询到fdset之后,循环遍历每个fd是否就绪
 * @param clients_fd
 * @param readfds
 */
static void recv_client_msg(int *clients_fd, fd_set *readfds) {
    char *buf = new char[bufflen];
    struct message_head head;
    for (size_t i = 0; i < IPC_MAX_CONN; ++i) {
        if (clients_fd[i] == -1) {
            continue;
        } else if (FD_ISSET(clients_fd[i], readfds)) {
//            int n = read(clients_fd[i], buf, 1024);
            int n = read(clients_fd[i], &head, sizeof(struct message_head));
            if (n <= 0) {
                FD_CLR(clients_fd[i], readfds);
                printf("one socket close\n");
                close(clients_fd[i]);
                clients_fd[i] = -1;
                continue;
            }
            printf("command is: %d, buffer length: %d\n", head.cmd, head.data_len);
            read(clients_fd[i], buf, head.data_len);
            sleep(3);
            char *ret = "processed";
            write(clients_fd[i], ret, strlen(ret));
            //handle_client_msg(clients_fd[i], &head, buf);
        }
    }
    delete [] buf;
}

/**
 * 在这里处理SGX业务
 * @param fd
 * @param buf
 */
static void handle_client_msg(int fd, struct message_head *head, char *buf) {

    switch (head->cmd) {
        case SWITCH_PASSWORD:
            break;
        case ENCRYPT_DATA:
            break;
        case DECRYPT_DATA:
            break;
        default:
            break;
    }

    int len, i;
    assert(buf);
    printf("recv buf is:%s\n", buf);
    len = strlen(buf);
    for (i=0; i<len; i++) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] += 'A'- 'a';
        }
    }
    write(fd, buf, strlen(buf));

}

int testsend()
{
    int listen_fd = socket_bind(IPADDRESS, PORT);
    int max_fd = -1;
    int nready;
    fd_set readfds;
    int clients_fd[IPC_MAX_CONN];

    memset(clients_fd, -1, sizeof(clients_fd));
    // select 方式实现IO复用
    while (true) {

        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        max_fd = listen_fd;

        for (size_t i=0; i < IPC_MAX_CONN; i++)
        {
            if (clients_fd[i] != -1) {
                FD_SET(clients_fd[i], &readfds);
                max_fd = clients_fd[i] > max_fd ? clients_fd[i] : max_fd;
            }
        }
        nready = select(max_fd+1, &readfds, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select error.");
            return 1;
        }
        if (FD_ISSET(listen_fd, &readfds)) {
            accpet_client(clients_fd, listen_fd);
        }
        recv_client_msg(clients_fd, &readfds);
    }

    return 0;
}

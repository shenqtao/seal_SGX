#ifndef _SGX_SERVER_H
#define _SGX_SERVER_H

#define IPADDRESS "0.0.0.0"
#define PORT 20186
#define IPC_MAX_CONN 1024
/**
 * 支持的命令枚�? */
typedef enum command {
    ENC_PARAMETER_POLYMOD,
    ENC_PARAMETER_COEFMOD,
    ENC_PARAMETER_PLAINMOD,
    PRIVATE_KEY,
    PUBLIC_KEY,
    ENCRYPT_DATA,
    DECRYPT_DATA
}command;

/**
 * 消息�?可以再扩�? */
struct message_head {
    command cmd;
    unsigned int data_len;
};


#endif

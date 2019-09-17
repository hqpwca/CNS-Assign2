#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

class Network {
public:
    Network();
    ~Network();

    int Listen_Receive(void *msg, int port);
    int Send(void *msg, int msg_len, std::string IP, int port);
};
#endif
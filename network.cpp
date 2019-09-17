#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "include/network.h"

Network::Network(){

}

int Network::Send(void *msg, int msg_len, std::string IP, int port){
    int sock;
    sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(IP.c_str());
    addr.sin_port = htons(port);
    memset(&(addr.sin_zero), '\0', 8);

    connect(sock, (sockaddr *)&addr, sizeof(addr));
    std::cerr << "Connecting " << IP << ":" << port << " to transfer data." << std::endl;
    send(sock, msg, msg_len, 0);
    std::cerr << "Sucuessfully sent data to the receiver." << std::endl;
    close(sock);
}

int Network::Listen_Receive(void *msg, int port){
    int sock, client;
    sockaddr_in addr, cli;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    memset(&(addr.sin_zero), '\0', 8);

    bind(sock, (sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);
    std::cerr << "Listening port " << port << ".\n";

    socklen_t len;
    client = accept(sock, (sockaddr *)&cli, &len);
    std::cerr << "Connect Accepted." << std::endl;
    size_t msg_len = recv(client, msg, 65536, 0);

    std::cerr << "Inbound file." << std::endl;

    return msg_len;
}

Network::~Network(){

}
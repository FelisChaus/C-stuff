#include <iostream>
#include <memory>

#include <sys/socket.h>
#include <netdb.h>

#include "getlistener.h"

void freeaddrinfolocal(struct addrinfo* ai) {
    std::cout << "freeaddrinfolocal invocation" << std::endl;
    freeaddrinfo(ai);
}

using addrinfo_t = std::unique_ptr<addrinfo, decltype(&freeaddrinfolocal)>;

int getlistener(const char* port) {
    struct addrinfo hints { .ai_family = AF_INET6, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE };
    struct addrinfo *bind_addr {nullptr};
    if(int rv = getaddrinfo(0, port, &hints, &bind_addr); 0 != rv) {
        std::cerr << "getaddrinfo(): " << gai_strerror(rv) << std::endl;
        return INVALID_SOCKET;
    }
    addrinfo_t addr(bind_addr, &freeaddrinfolocal);
    int listener = socket(
        bind_addr->ai_family,
        bind_addr->ai_socktype, 
        bind_addr->ai_protocol
    );
    if(INVALID_SOCKET == listener) {
        std::cerr << "socket(): " << strerror(errno) << std::endl;
        return INVALID_SOCKET;
    }
    // Switching on 4&6 dual-stack socket.
    if(int option = 0; setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&option, sizeof(option))) {
        std::cerr << "setsockopt(): " << strerror(errno) << std::endl;
        return INVALID_SOCKET;
    }
    if(int option = 1; setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int))) {
        std::cerr << "setsockopt(SO_REUSEADDR): " << strerror(errno) << std::endl;
        return INVALID_SOCKET;
    }
    if(int option = 1; setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int))) {
        std::cerr << "setsockopt(SO_REUSEPORT): " << strerror(errno) << std::endl;
        return INVALID_SOCKET;
    }
    if(bind(listener, bind_addr->ai_addr, bind_addr->ai_addrlen)) {
        std::cerr << "bind(): " << strerror(errno) << std::endl;
        return INVALID_SOCKET;
    }
    return listener;
}
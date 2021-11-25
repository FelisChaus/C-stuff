#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <iostream>

const int INVALID_SOCKET = -1;
const char PORT[] = "8080";

static const char favicon[] = "GET /favicon.ico HTTP/1.1";
static const char response_header[] =
    "HTTP/1.1 200 OK\r\n"
    "Connection: close\r\n"
    "Content-Type: text/plain\r\n\r\n"
    "Local time is: ";

/*
 * References:
 *
 * Lewis Van Winkle - Hands-On Network Programming with C
 * https://github.com/codeplea/Hands-On-Network-Programming-with-C
 * 
 * W. Richard Stevens - Unix Network Programming
 */

/*
 * http://127.0.0.1:8080
 * http://[::1]:8080
 */

static void getlocaladapters() {
    struct ifaddrs *ifaddr;
    if(getifaddrs(&ifaddr) == -1) {
        std::cerr << "getifaddrs: " << strerror(errno) << std::endl;
        return;
    }
    for(struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if(!ifa->ifa_addr) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        if(AF_INET == family || AF_INET6 == family) {
            std::cout << ifa->ifa_name << "\t" << (family == AF_INET ? "AF_INET" : "AF_INET6") << "\t";
            if(family == AF_INET || family == AF_INET6) {
                char host[NI_MAXHOST];
                int rv = getnameinfo(
                    ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    host, 
                    NI_MAXHOST,
                    0, 
                    0, 
                    NI_NUMERICHOST
                );
                if(rv != 0) {
                    std::cerr << "getnameinfo(): " << gai_strerror(rv) << std::endl;
                    freeifaddrs(ifaddr);
                    return;
                }
                std::cout << host << std::endl;
            }
        }
    }
    freeifaddrs(ifaddr);
}

static int getlistener() {
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *bind_addr;
    int rv = getaddrinfo(0, PORT, &hints, &bind_addr);
    if(0 != rv) {
        std::cerr << "getaddrinfo(): " << gai_strerror(rv) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    int listener = socket(
        bind_addr->ai_family,
        bind_addr->ai_socktype, 
        bind_addr->ai_protocol
    );
    if(-1 == listener) {
        std::cerr << "socket(): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    int option = 0; // Switching on 4&6 dual-stack socket.
    if(setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&option, sizeof(option))) {
        std::cerr << "setsockopt(): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    int enable = 1;
    if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int))) {
        std::cerr << "setsockopt(SO_REUSEADDR): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    if(setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int))) {
        std::cerr << "setsockopt(SO_REUSEPORT): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    if(bind(listener, bind_addr->ai_addr, bind_addr->ai_addrlen)) {
        std::cerr << "bind(): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    freeaddrinfo(bind_addr);
    return listener;
}

static bool read(int peer) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(peer, &readfds);
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 500000;
    int rv = select(peer + 1, &readfds, 0, 0, &timeout);
    if(-1 == rv) {
        std::cerr << "select(): " << strerror(errno) << std::endl;
        return false;
    }
    if(0 == rv) {
        std::cerr << "select(): timeout" << std::endl;
        return false;
    }
    // Here readfds set is modified by select() and only singnalling sockets remain.
    if(FD_ISSET(peer, &readfds)) {
        char request[1024] = {0};
        int bytes_received = recv(peer, request, 1024, 0);
        if(-1 == bytes_received) {
            std::cerr << "recv(): " << strerror(errno) << std::endl;
            return false;
        }
        if(bytes_received > 0) {
            if(strstr(request, favicon)) {
                std::cout << favicon << std::endl;
            } else {
                std::cout << request << std::endl;
            }
        }
    }
    return true;
}

static bool send(int peer, const void *buf, size_t len) {
    auto p = const_cast<unsigned char*>(static_cast<const unsigned char*>(buf));
    auto l = len;
    while(l > 0) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(peer, &writefds);
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 500000;
        int rv = select(peer + 1, 0, &writefds, 0, &timeout);
        if(-1 == rv) {
            std::cerr << "select(): " << strerror(errno) << std::endl;
            return false;
        }
        if(0 == rv) {
            std::cerr << "select(): timeout" << std::endl;
            return false;
        }
        // Here writefds set is modified by select() and only singnalling sockets remain.
        if(FD_ISSET(peer, &writefds)) {
            int bytes_sent = send(peer, p, l, 0);
            if(-1 == bytes_sent) {
                std::cerr << "send(): " << strerror(errno) << std::endl;
                return false;
            }
            l -= bytes_sent;
            p += bytes_sent;
        }
    }
    return true;
}

static void response(int peer, struct sockaddr* client_addr, socklen_t client_len) {
    char addr_buff[1024];
    getnameinfo(client_addr, client_len, addr_buff, sizeof(addr_buff), 0, 0, NI_NUMERICHOST);
    std::cout << "Connected: " << addr_buff << std::endl;
    if(!read(peer)) {
        return;
    }
    if(send(peer, response_header, strlen(response_header))) {
        time_t timer;
        time(&timer);
        char *time_msg = ctime(&timer);
        send(peer, time_msg, strlen(time_msg));
    }
}

static void listen(int listener) {
    if(listen(listener, -1) < 0) {
        std::cerr << "listen(): " << strerror(errno) << std::endl;
        return;
    }
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    while(true) {
        int peer = accept(listener, (struct sockaddr*)&client_addr, &client_len);
        if(INVALID_SOCKET == peer) {
            std::cerr << "accept(): " << strerror(errno) << std::endl;
            return;
        }
        int pid = fork();
        if(0 == pid) { // Child process
            response(peer, (struct sockaddr*)&client_addr, client_len);
            close(peer);
            close(listener);
            exit(0);
        }
        close(peer);
    }
}

int main() {
    std::cout << APP_VERSION << std::endl;
    getlocaladapters();
    int listener = getlistener();
    if(INVALID_SOCKET == listener) {
        return 1;
    }
    listen(listener);
    close(listener);
}
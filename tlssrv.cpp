#include <iostream>

#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * References:
 *
 * Lewis Van Winkle - Hands-On Network Programming with C
 * https://github.com/codeplea/Hands-On-Network-Programming-with-C
 * 
 * Zakir Durumeric - Parsing X.509 Certificates with OpenSSL and C
 * https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 * 
 * W. Richard Stevens - Unix Network Programming
 */

/*
 * openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
 * openssl x509 -text -noout -in cert.pem
 */

const int INVALID_SOCKET = -1;
const char PORT[] = "8080";

static const char favicon[] = "GET /favicon.ico HTTP/1.1";
static const char response_header[] =
    "HTTP/1.1 200 OK\r\n"
    "Connection: close\r\n"
    "Content-Type: text/plain\r\n\r\n"
    "Local time is: ";

static int getlistener() {
    struct addrinfo hints = { .ai_family = AF_INET6, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE };
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
    if(INVALID_SOCKET == listener) {
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
    option = 1;
    if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int))) {
        std::cerr << "setsockopt(SO_REUSEADDR): " << strerror(errno) << std::endl;
        freeaddrinfo(bind_addr);
        return INVALID_SOCKET;
    }
    if(setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int))) {
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

static void response(SSL_CTX *ctx, int peer, struct sockaddr* client_addr, socklen_t client_len) {
    char addr_buff[1024];
    getnameinfo(client_addr, client_len, addr_buff, sizeof(addr_buff), 0, 0, NI_NUMERICHOST);
    std::cout << "Connected: " << addr_buff << std::endl;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "SSL_new() failed" << std::endl;
        return;
    }
    SSL_set_fd(ssl, peer);
    int rv;
    while(true) {
        rv = SSL_accept(ssl);
        if(rv <= 0) {
            int e = SSL_get_error(ssl, rv);
            if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        break;
    }
    if (rv <= 0) {
        std::cerr << "SSL_accept() failed: " << rv << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        close(peer);
        SSL_free(ssl);
        return;
    }
    std::cout << "SSL/TLS is using " << SSL_get_cipher(ssl) << std::endl;
    char request[4096];
    int received = SSL_read(ssl, request, sizeof(request));
    int sent = SSL_write(ssl, response_header, strlen(response_header));
    time_t timer;
    time(&timer);
    char *time_msg = ctime(&timer);
    sent = SSL_write(ssl, time_msg, strlen(time_msg));
    SSL_shutdown(ssl);
    close(peer);
    SSL_free(ssl);
}

static void listen(SSL_CTX *ctx, int listener) {
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
            response(ctx, peer, (struct sockaddr*)&client_addr, client_len);
            close(peer);
            close(listener);
            exit(0);
        }
        close(peer);
    }
}

int main() {
    std::cout << "Application version: " << APP_VERSION << std::endl;
    std::cout << "CMAKE_CURRENT_SOURCE_DIR: " << CMAKE_CURRENT_SOURCE_DIR << std::endl;
    std::cout << "OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char buff[4096] = {};
    sprintf(buff, "%s/cert.pem", CMAKE_CURRENT_SOURCE_DIR);
    if (!SSL_CTX_use_certificate_file(ctx, buff, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }
    sprintf(buff, "%s/key.pem", CMAKE_CURRENT_SOURCE_DIR);
    if(!SSL_CTX_use_PrivateKey_file(ctx, buff, SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int listener = getlistener();
    if(INVALID_SOCKET == listener) {
        SSL_CTX_free(ctx);
        return 1;
    }

    listen(ctx, listener);
    close(listener);
    SSL_CTX_free(ctx);
}
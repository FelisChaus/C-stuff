
#include <iostream>
#include <memory>

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

const int INVALID_SOCKET = -1;

#if 0
const char HOST[] = "openssl.org";
const char PORT[] = "443";
#else
const char HOST[] = "::1";
const char PORT[] = "8080";
#endif

static void openssl_error(const char* hint) {
    unsigned long e;
    while ((e = ERR_peek_error()) != 0) {
        std::cerr << hint << ERR_lib_error_string(e) << std::endl;
        std::cerr << hint << ERR_reason_error_string(e) << std::endl;
        ERR_get_error();
    }
}

static void SSL_CTX_free_local(SSL_CTX *ctx) {
    std::cout << "SSL_CTX_free" << std::endl;
    SSL_CTX_free(ctx);
}

static void SSL_shutdown_local(SSL *ssl) {
    std::cout << "SSL_shutdown & free" << std::endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    std::cout << "Application version: " << APP_VERSION << std::endl;
    std::cout << "OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free_local)> ctx { SSL_CTX_new(TLS_client_method()), &SSL_CTX_free_local };
    if (!ctx) {
        openssl_error("SSL_CTX_new(): ");
        return 1;
    }

    if (!SSL_CTX_load_verify_locations(ctx.get(), "cert.pem", 0)) {
        std::cout << "SSL_CTX_load_verify_locations() failed" << std::endl;
    }

    struct addrinfo hints { .ai_socktype = SOCK_STREAM };
    struct addrinfo *peer_addr {nullptr};
    if (auto rv = getaddrinfo(HOST, PORT, &hints, &peer_addr); 0 != rv) {
        std::cerr << "getaddrinfo(): " << gai_strerror(rv) << std::endl;
        freeaddrinfo(peer_addr);
        return 1;
    }

    char address_buffer[1024];
    char service_buffer[1024];
    getnameinfo(peer_addr->ai_addr, peer_addr->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);
    std::cout << "Address: " << address_buffer << std::endl;
    std::cout << "Service: " << service_buffer << std::endl;

    int peer = socket(peer_addr->ai_family, peer_addr->ai_socktype, peer_addr->ai_protocol);
    if (INVALID_SOCKET == peer) {
        std::cerr << "socket(): " << strerror(errno) << std::endl;
        freeaddrinfo(peer_addr);
        return 1;
    }

    // Async & nonblocking connect with timeout.
    int flags = fcntl(peer, F_GETFL, 0);
    fcntl(peer, F_SETFL, flags | O_NONBLOCK);
    if (connect(peer, peer_addr->ai_addr, peer_addr->ai_addrlen)) {
        if (errno != EINPROGRESS) {
            std::cerr << "connect(): " << strerror(errno) << std::endl;
            freeaddrinfo(peer_addr);
            return 1;
        }
    }
    freeaddrinfo(peer_addr);
    fcntl(peer, F_SETFL, flags);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(peer, &set);
    struct timeval timeout { .tv_sec = 5, .tv_usec = 0 };
    select(peer + 1, 0, &set, 0, &timeout);

    std::unique_ptr<SSL, decltype(&SSL_shutdown_local)> ssl { SSL_new(ctx.get()), &SSL_shutdown_local };
    if (!ssl) {
        openssl_error("SSL_new(): ");
        return 1;
    }

    if (!SSL_set_tlsext_host_name(ssl.get(), HOST)) {
        openssl_error("SSL_set_tlsext_host_name(): ");
        return 1;
    }

    SSL_set_fd(ssl.get(), peer);
    if (SSL_connect(ssl.get()) == -1) {
        openssl_error("SSL_connect(): ");
        return 1;
    }

    std::cout << "SSL/TLS is using " << SSL_get_cipher(ssl.get()) << std::endl;

    X509 *cert = SSL_get_peer_certificate(ssl.get());
    if (!cert) {
        openssl_error("SSL_get_peer_certificate(): ");
        return 1;
    }
    if (char *t = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); t) {
        std::cout << "Subject: " << t << std::endl;
        OPENSSL_free(t);
    }

    if (char *t = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); t) {
        std::cout << "Issuer: " << t << std::endl;
        OPENSSL_free(t);
    }
    X509_free(cert);

    if (auto vr = SSL_get_verify_result(ssl.get()); vr == X509_V_OK) {
        std::cout << "Certificates verified successfully" << std::endl;
    } else {
        std::cout << "Could not verify certificates: " << vr << std::endl;
        openssl_error("SSL_get_verify_result: ");
    }

    char buffer[2048];
    sprintf(buffer, "GET / HTTP/1.1\r\n");
    sprintf(buffer + strlen(buffer), "Host: %s:%s\r\n", HOST, PORT);
    sprintf(buffer + strlen(buffer), "Connection: close\r\n");
    sprintf(buffer + strlen(buffer), "User-Agent: https_simple\r\n");
    sprintf(buffer + strlen(buffer), "\r\n");

    SSL_write(ssl.get(), buffer, strlen(buffer));
    while(1) {
        if (int received = SSL_read(ssl.get(), buffer, sizeof(buffer)); received < 1) {
            std::cout << std::endl << "Connection closed by peer" << std::endl;
            break;
        } else {
            // Compiler does not support std::format C++ 20 feature.
            printf("Received (%d bytes): '%.*s'\n", received, received, buffer);
        }
    }

    close(peer);
}
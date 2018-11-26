#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <sys/time.h>

#include <inttypes.h>

#include <errno.h>

#include <sodium.h>

#include <unilink.h>

int     create_tcp_server(int *tcp_fd, const char *port) {
    int             s, tcp_sock;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    if (tcp_fd == NULL) {
        fprintf(stderr,
            "create_tcp_server(); tcp_fd == NULL\n");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    s = getaddrinfo(NULL, port, &hints, &res);
    if (s != 0) {
        fprintf(stderr,
            "create_tcp_server(); getaddrinfo failed\n");
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        tcp_sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (tcp_sock < 0)
            continue;

        s = bind(tcp_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
            break;

        close(tcp_sock);
    }

    if (rp == NULL) {
        freeaddrinfo(res);

        fprintf(stderr,
            "create_tcp_server(); bind failed\n");
        return -2;
    }

    *tcp_fd = tcp_sock;
    freeaddrinfo(res);
    return 0;
}

int     create_udp_server(int *udp_fd, const char *port) {
    int             s, udp_sock;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    if (udp_fd == NULL) {
        fprintf(stderr,
            "create_udp_server(); udp_fd == NULL\n");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    s = getaddrinfo(NULL, port, &hints, &res);
    if (s != 0) {
        fprintf(stderr,
            "create_udp_server(); getaddrinfo failed\n");
        return -2;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        udp_sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (udp_sock < 0)
            continue;

        s = bind(udp_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
            break;

        close(udp_sock);
    }

    if (rp == NULL) {
        freeaddrinfo(res);

        fprintf(stderr,
            "create_udp_server(); bind failed\n");
        return -3;
    }

    *udp_fd = udp_sock;
    freeaddrinfo(res);
    return 0;
}

void    server_loop(int udp_fd, int tcp_fd) {
    unsigned char           buf[USHRT_MAX];
    ssize_t                 size;
    fd_set                  rfds;
    struct timeval          tv;
    int                     must_quit;
    int                     s;
    struct sockaddr_storage src_addr;
    socklen_t               addrlen;

    must_quit = 0;
    while (!must_quit) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = 300;
        tv.tv_usec = 0;

        s = select(fd + 1, &rfds, NULL, NULL, &tv);
        switch (s) {
            case 1:
                addrlen = sizeof src_addr;
                size = recvfrom(fd, buf, sizeof buf, 0,
                            (struct sockaddr *) &src_addr, &addrlen);
                if (size == -1) {
                    fprintf(stderr, "server_loop(); recvfrom failed\n");
                    must_quit = 1;
                    break;
                }
                buf[size] = 0;
                printf("incoming data: %s\n", buf);
                // process incoming data
                sendto(fd, buf, strlen((char *)buf), 0,
                    (struct sockaddr *) &src_addr, addrlen);
                break;
            case 0:
                // periodic tasks every tv.tv_sec seconds
                printf("periodic task\n");
                break;
            case -1:
                fprintf(stderr, "server_loop(); select failed\n");
                must_quit = 1;
                break;
        }
    }
}



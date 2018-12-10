#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <sys/time.h>

#include <poll.h>
#include <signal.h>

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

    s = listen(tcp_sock, 1024);
    if (s == -1) {
        close(tcp_sock);
        freeaddrinfo(res);
        fprintf(stderr,
            "create_tcp_server(); listen failed\n");
        return -3;
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

ssize_t is_complete_command(unsigned char *buf, size_t size) {
    int             n_line, x;
    long int        end_size;
    size_t          line_len;
    unsigned char   *p, *k, *j;

    for (line_len = 0, n_line = 0, p = buf;
            p < buf + size;
            ++p) {
        if (*p == '\n') {
            ++n_line;
            // printf("%s\n", "++n_line");
            if (line_len == 0 && n_line >= 5) {
                // printf("%s\n", "line_len == 0 && n_line >= 5");
                j = p + 1;
                k = p;
                for (x = 0; k >= buf; --k) {
                    if (*k == '\n') {
                        ++x;
                        // printf("%s\n", "++x");
                    }
                    if (x == 3) {
                        // printf("%s\n", "x == 3");
                        ++k;
                        end_size = strtol((const char *)k,
                            NULL, 10);
                        if (end_size >= 0 &&
                            end_size <= (buf + size - j)) {
                            return j - buf + end_size;
                        } else {
                          /*  printf("%s\n", "end_size < 0"
                                "|| end_size <= (buf + size - j)");
                         */ return -1;
                        }
                    }
                }
                return -1;
            }
            // printf("%s\n", "line_len = 0");
            line_len = 0;
        } else {
            // printf("%s\n", "++line_len");
            ++line_len;
        }
    }
    return -1;
}

int     server_loop(int udp_fd, int tcp_fd) {
    static struct pollfd    fds[2050];
    static unsigned char    buf[65535];
    int                     s;
    size_t                  nfds, i;
    struct sockaddr_storage sa;
    socklen_t               sa_len;

    nfds = 0;
    fds[0].fd = udp_fd;
    fds[0].events = POLLIN;
    ++nfds;
    fds[1].fd = tcp_fd;
    fds[1].events = POLLIN;
    ++nfds;
    for (;;) {
        s = poll(fds, nfds, 300000);
        if (s > 0) {
            for (i = 0; i < nfds; ++i) {
                if (fds[i].revents & POLLIN) {
                    s = fds[i].fd;
                    if (s == udp_fd) {
                        // read and send to handler
                        (void)buf;
                        (void)sa;
                        (void)sa_len;
                    } else if (s == tcp_fd) {
                        // accept and add to fds
                        if (nfds < sizeof fds / sizeof *fds) {
                            s = accept(tcp_fd, NULL, NULL);
                            if (s < 0) {
                                fprintf(stderr, "server_loop();"
                                    " accept failed\n");
                            } else {
                                fds[nfds].fd = s;
                                fds[nfds].events = POLLIN;
                                ++nfds;
                            }
                        }
                    } else {
                        // read tcp stream and bufferize
                        // if incomplete
                        (void)buf;
                        (void)sa;
                        (void)sa_len;
                    }
                }
                
            }
        } else if (s == 0) {
            // timed out.
        }
    }
}

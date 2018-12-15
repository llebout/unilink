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

#include <time.h>

#include <errno.h>

#include <sodium.h>

#include <queue.h>
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
            if (line_len == 0 && n_line >= 5) {
                j = p + 1;
                k = p;
                for (x = 0; k >= buf; --k) {
                    if (*k == '\n') {
                        ++x;
                    }
                    if (x == 3) {
                        ++k;
                        end_size = strtol((const char *)k,
                                NULL, 10);
                        if (end_size >= 0 &&
                                end_size <= (buf + size - j)) {
                            return j - buf + end_size;
                        } else {
                            return -1;
                        }
                    }
                }
                return -1;
            }
            line_len = 0;
        } else {
            ++line_len;
        }
    }
    return -1;
}

int     server_loop(int udp_fd, int tcp_fd) {
    static struct pollfd            fds[2050];
    static unsigned char            buf[65535];
    unsigned char                   *buftmp;
    int                             s, fdtmp;
    time_t                          run_check;
    size_t                          nfds, i, k;
    struct sockaddr_storage         sa;
    socklen_t                       sa_len;
    struct fd_buffer                *fb;
    LIST_HEAD(fb_head, fd_buffer)   fb_que
        = LIST_HEAD_INITIALIZER(fb_que);

    LIST_INIT(&fb_que);
    nfds = 0;
    fds[0].fd = udp_fd;
    fds[0].events = POLLIN;
    ++nfds;
    fds[1].fd = tcp_fd;
    fds[1].events = POLLIN;
    ++nfds;
    run_check = time(NULL);
    for (;;) {
        s = poll(fds, nfds, 1000);
        if (s > 0) {
            for (i = 0; i < nfds; ++i) {
                s = fdtmp = fds[i].fd;

                if (fds[i].revents & POLLNVAL) {
                    goto discard_fd; 
                } else if (fds[i].revents & POLLERR) {
                    goto discard_fd;
                } else if (fds[i].revents & POLLHUP) {
                    goto discard_fd;
                } else if (fds[i].revents & POLLIN) {
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
                                // we modified fds and nfds so break
                                break;
                            }
                        }
                    } else {
                        memset(&sa, 0, sizeof sa);
                        sa_len = sizeof sa;
                        s = recvfrom(fds[i].fd, buf,
                                sizeof buf, 0,
                                (struct sockaddr *) &sa, &sa_len);
                        if (s == -1) {
                            fprintf(stderr, "server_loop();"
                                    " recvfrom failed\n");
                            goto discard_fd;
                        } else if (s == 0) {
                            goto discard_fd;
                        }

                        LIST_FOREACH(fb, &fb_que, e) {
                            if (fb->fd == fds[i].fd) {
                                // don't allow buffer to grow past
                                // 128KB for a single incomplete
                                // command
                                if (fb->size + s > 131072)
                                    goto discard_fd;

                                buftmp = realloc(fb->buf,
                                        fb->size + s);
                                if (buftmp == NULL) {
                                    fprintf(stderr, "server_loop();"
                                            " realloc failed\n");
                                    goto discard_fd;
                                }
                                memcpy(buftmp + fb->size,
                                        buf, s);
                                fb->buf = buftmp;
                                fb->size += s;
                                fb->last_active = time(NULL);

                                if (is_complete_command(fb->buf,
                                            fb->size) > 0) {
                                    //call handler
                                    goto flush_buffer;
                                }
                                goto next_fd;
                            }
                        }
                        //no active buffer found

                        if (is_complete_command(buf, s) > 0) {
                            //call handler
                            break;
                        }

                        fb = calloc(1, sizeof *fb);
                        if (fb == NULL) {
                            fprintf(stderr, "server_loop();"
                                    " calloc failed\n");
                            goto discard_fd;
                        }

                        fb->fd = fds[i].fd;
                        fb->size = s;
                        fb->last_active = time(NULL);

                        fb->buf = malloc(s);
                        if (fb->buf == NULL) {
                            free(fb);
                            fprintf(stderr, "server_loop();"
                                    " malloc failed\n");
                            goto discard_fd;
                        }

                        memcpy(fb->buf, buf, s);

                        LIST_INSERT_HEAD(&fb_que, fb, e);
                    }
                }
next_fd:
                continue; // don't go there
discard_fd:
                close(fds[i].fd);

                --nfds;
                for (k = i; k < nfds; ++k) {
                    fds[k].fd = fds[k+1].fd;
                }

flush_buffer:
                LIST_FOREACH(fb, &fb_que, e) {
                    if (fb->fd == fdtmp) {
                        LIST_REMOVE(fb, e);
                        free(fb->buf);
                        free(fb);
                        break;
                    }
                }
                break; // we modified fds and nfds so break
            }
        } else if (s == 0) {
            // timed out.
        }

        if (run_check > (time(NULL) - 30)) {
            continue;
        }
        run_check = time(NULL);

re_iterate:
        LIST_FOREACH(fb, &fb_que, e) {
            if (fb->last_active < (time(NULL) - 30)) {
                LIST_REMOVE(fb, e);

                close(fb->fd);

                for (i = 0; i < nfds; ++i) {
                    if (fds[i].fd == fb->fd) {
                        --nfds;
                        for (k = i; k < nfds; ++k) {
                            fds[k].fd = fds[k+1].fd;
                        }
                        break;
                    }
                }

                free(fb->buf);
                free(fb);
                goto re_iterate;
            }
        }

    }
}

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

extern LIST_HEAD(cmd_handlers, cmd_handler) handler_que;

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

ssize_t is_complete_command(unsigned char *buf, size_t size,
                unsigned char **start_of_end) {
    int             n_line, x;
    long int        end_size;
    size_t          line_len;
    unsigned char   *p, *k, *j;

    for (line_len = 0, n_line = 0, p = buf;
            p < buf + size;
            ++p) {
        if (*p == '\n') {
            if (n_line == 0
                && strncmp((const char *)buf, UNILINK_NETWORK_MAGIC,
                    p - buf - 1) != 0) {
                fprintf(stderr, "UNILINK_NETWORK_MAGIC invalid\n");
                return -1;
            }
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
                            *start_of_end = j;
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

time_t  elapsed_seconds() {
    int             s;
    struct timespec ts;

    s = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (s == -1) {
        fprintf(stderr, "elapsed_seconds(); clock_gettime failed"
                "\n");
        return 0;
    }
    return ts.tv_sec;
}

int     parse_cmdinfo(unsigned char *buf, size_t size,
                unsigned char *start_of_end, struct cmdinfo *ci) {
    FILE            *f;
    size_t          n_lines, i, n;
    ssize_t         s;
    unsigned char   *p;
    char            **lines;

    if (ci == NULL) {
        fprintf(stderr, "parse_cmdinfo(); ci == NULL\n");
        return -1;
    }

    for (n_lines = 0, p = buf; p != NULL
                && p < start_of_end; ++n_lines, ++p) {
        p = memchr(p, '\n', size - (p - buf));
    }

    lines = calloc(n_lines + 1, sizeof *lines);
    if (lines == NULL) {
        fprintf(stderr, "parse_cmdinfo(); calloc failed\n");
        return -2;
    }

    f = fmemopen(buf, size, "r");
    if (f == NULL) {
        fprintf(stderr, "parse_cmdinfo(); fmemopen failed\n");
        return -3;
    }

    for (n = 0, i = 0; i < n_lines
            && (s = getline(&lines[i], &n, f)) != -1; ++i, n = 0);
    if (i != n_lines) {
        fprintf(stderr, "parse_cmdinfo(); invalid cmdinfo\n");
        return -4;
    }

    ci->lines = lines;
    
    if (sscanf(lines[1], "%"SCNu32, &ci->type) != 1) {
        fprintf(stderr, "parse_cmdinfo(); sscanf failed\n");
        return -5;
    }

    ci->is_reply = atoi(lines[2]) ? 1 : 0;
    ci->end_size = size - (start_of_end - buf);
    ci->end = start_of_end;
    return 0;
}

int     server_loop(int udp_fd, int tcp_fd) {
    static struct pollfd            fds[2050];
    static unsigned char            buf[65535];
    unsigned char                   *buftmp, *start_of_end;
    int                             s, fdtmp, found_handler;
    time_t                          run_check;
    size_t                          nfds, i, k;
    ssize_t                         msg_size;
    struct sockaddr_storage         sa;
    socklen_t                       sa_len;
    struct cmdinfo                  ci;
    struct cmd_handler              *ch;
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
    run_check = elapsed_seconds();
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
                                fb->last_active = elapsed_seconds();

                                printf("grow fd_buffer (%d) of %u"
                                        ", size is now %lu\n",
                                        fb->fd, s, fb->size);

                                if ((msg_size = 
                                        is_complete_command(fb->buf,
                                            fb->size,
                                            &start_of_end)) > 0) {
                                    //call handler
                                    if (parse_cmdinfo(fb->buf,
                                        msg_size,
                                        start_of_end, &ci) >= 0) {
                                        memcpy(&ci.sa, &sa, sa_len);
                                        ci.sa_len = sa_len;
                                        ci.fd = fds[i].fd;
                                        ci.is_tcp = 1;

                                        found_handler = 0;
                                        LIST_FOREACH(ch,
                                                &handler_que, e) {
                                            if (ch->type
                                                == ci.type) {
                                                found_handler = 1;
                                                printf(
                                                    "handler for "
                                                    "command of "
                                                    "type %"
                                                    SCNu32" "
                                                    "returned %d\n",
                                                    ci.type,
                                                    (ch->f)(&ci,
                                                        &ch->
                                                    handler_data));
                                                break;
                                            }
                                        }
                                        if (found_handler == 0) {
                                        printf("unhandled "
                                            "command of type %"
                                            SCNu32"\n",
                                            ci.type);
                                        }
                                    }

                                    goto flush_buffer;
                                }
                                goto next_fd;
                            }
                        }
                        //no active buffer found

                        if ((msg_size = is_complete_command(buf, s,
                                    &start_of_end)) > 0) {
                            //call handler                           
                            if (parse_cmdinfo(fb->buf, msg_size,
                                    start_of_end, &ci) >= 0) {
                                memcpy(&ci.sa, &sa, sa_len);
                                ci.sa_len = sa_len;
                                ci.fd = fds[i].fd;
                                ci.is_tcp = 1;

                                found_handler = 0;
                                LIST_FOREACH(ch, &handler_que, e) {
                                    if (ch->type == ci.type) {
                                        found_handler = 1;
                                        printf("handler for "
                                            "command of type %"
                                            SCNu32" "
                                            "returned %d\n",
                                            ci.type,
                                            (ch->f)(&ci,
                                                &ch->handler_data));
                                        break;
                                    }
                                }
                                if (found_handler == 0) {
                                    printf("unhandled "
                                            "command of type %"
                                            SCNu32"\n",
                                            ci.type);
                                }
                            }
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
                        fb->last_active = elapsed_seconds();

                        fb->buf = malloc(s);
                        if (fb->buf == NULL) {
                            free(fb);
                            fprintf(stderr, "server_loop();"
                                    " malloc failed\n");
                            goto discard_fd;
                        }

                        memcpy(fb->buf, buf, s);

                        LIST_INSERT_HEAD(&fb_que, fb, e);
                        printf("new fd_buffer (%d) with size %lu\n",
                                fb->fd, fb->size);
                    }
                }
next_fd:
                continue; // don't go there
discard_fd:
                printf("discarding fd (%d)\n", fds[i].fd);

                shutdown(fds[i].fd, SHUT_RDWR);
                close(fds[i].fd);

                --nfds;
                for (k = i; k < nfds; ++k) {
                    fds[k].fd = fds[k+1].fd;
                }

flush_buffer:
                LIST_FOREACH(fb, &fb_que, e) {
                    if (fb->fd == fdtmp) { 
                        printf("flushing fd_buffer (%d)"
                                " of size %lu\n", fb->fd, fb->size);
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

        if (run_check > (elapsed_seconds() - 30)) {
            continue;
        }
        run_check = elapsed_seconds();

re_iterate:
        LIST_FOREACH(fb, &fb_que, e) {
            if (fb->last_active < (elapsed_seconds() - 30)) {
                LIST_REMOVE(fb, e);

                printf("discarding fd (%d)\n", fb->fd);

                shutdown(fb->fd, SHUT_RDWR);
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
                printf("flushing fd_buffer (%d)"
                        " of size %lu\n", fb->fd, fb->size);
                free(fb->buf);
                free(fb);
                goto re_iterate;
            }
        }
    }
}

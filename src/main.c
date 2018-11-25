#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/select.h>
#include <sys/time.h>

#include <inttypes.h>

#include <errno.h>

#include <sodium.h>

#include "unilink.h"

int     create_server(int *fd, const char *port) {
    int             s, sock;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    if (fd == NULL) {
        fprintf(stderr,
            "create_server(); fd == NULL\n");
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
            "create_server(); getaddrinfo failed\n");
        return -2;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        s = bind(sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
            break;

        close(sock);
    }

    if (rp == NULL) {
        freeaddrinfo(res);

        fprintf(stderr,
            "create_server(); bind failed\n");
        return -3;
    }

    *fd = sock;
    freeaddrinfo(res);
    return 0;
}

void    server_loop(int fd) {
    unsigned char   buf[USHRT_MAX];
    ssize_t         size;
    fd_set          rfds;
    struct timeval  tv;
    int             must_quit;
    int             s;
    struct sockaddr src_addr;
    socklen_t       addrlen;

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
                            &src_addr, &addrlen);
                if (size == -1) {
                    fprintf(stderr, "server_loop(); recvfrom failed\n");
                    must_quit = 1;
                    break;
                }
                buf[size] = 0;
                printf("incoming data: %s\n", buf);
                // process incoming data
                sendto(fd, buf, strlen((char *)buf), 0, &src_addr, addrlen);
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

int     read_peerinfo(struct peerinfo *pi) {
    FILE        *fp;
    int         nline, port, ret;
    char        *line;
    const char  *b64_end;
    void        *bin;
    size_t      n, bin_len, b64_len;
    ssize_t     s;

    if (pi == NULL) {
        fprintf(stderr, "read_peerinfo(); pi == NULL\n");
        return -1;
    }

    fp = fopen(UNILINK_PEERINFO, "r");
    if (fp == NULL) {
        fprintf(stderr, "read_peerinfo(); fopen failed\n");
        return -2;
    }

    ret = 0;
    for (line = NULL, nline = 0;
                ret >= 0 && (s = getline(&line, &n, fp)) != -1; ++nline) {
        if (s == 0) {
            fprintf(stderr, "read_peerinfo(); empty line\n");
            ret = -3;
            break;
        }
        if (line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = 0;
        }
        switch (nline) {
            case 0:
                port = atoi(line);
                if (port > 0 && port < 65535) {
                    pi->port = strdup(line);
                    if (pi->port == NULL) {
                        fprintf(stderr,
                            "read_peerinfo(); port strdup failed\n");
                        ret = -4;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid port\n");
                    ret = -5;
                }
                break;
            case 1:
                if (strcmp(line, "x25519") == 0) {
                    pi->alg_pk = strdup(line);
                    if (pi->alg_pk == NULL) {
                        fprintf(stderr,
                            "read_peerinfo(); pk strdup failed\n");
                        ret = -6;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid alg_pk\n");
                    ret = -7;
                }
                break;
            case 2:
                b64_len = strlen(line);
                /*
                    allocates theoretical maximum decoded length,
                    wastes some space but reduces code complexity.
                */
                bin = malloc(b64_len/4*3+2);
                
                if (bin == NULL) {
                    fprintf(stderr,
                        "read_peerinfo(); bin malloc failed\n");
                    ret = -8;
                } else {
                    if (sodium_base642bin(
                            bin,
                            b64_len/4*3+2,
                            line,
                            b64_len,
                            NULL,
                            &bin_len,
                            &b64_end,
                            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
                        ) == -1 || b64_end != line + b64_len - 1) {
                        fprintf(stderr,
                            "read_peerinfo(); invalid pk\n");
                        free(bin);
                        ret = -9;
                    } else {
                        pi->pk_size = bin_len;
                        pi->pk = bin;
                    }
                }
                break;
            case 3:
                if (strcmp(line, "x25519") == 0) {
                    pi->master_alg_pk = strdup(line);
                    if (pi->master_alg_pk == NULL) {
                        fprintf(
                            stderr,
                            "read_peerinfo(); master_pk strdup failed\n"
                        );
                        ret = -10;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid master_alg_pk\n");
                    ret = -11;
                }
                break;
            case 4:
                b64_len = strlen(line);
                /*
                    allocates theoretical maximum decoded length,
                    wastes some space but reduces code complexity.
                */
                bin = malloc(b64_len/4*3+2);
                
                if (bin == NULL) {
                    fprintf(stderr,
                        "read_peerinfo(); bin malloc failed\n");
                    ret = -12;
                } else {
                    if (sodium_base642bin(
                            bin,
                            b64_len/4*3+2,
                            line,
                            b64_len,
                            NULL,
                            &bin_len,
                            &b64_end,
                            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
                        ) == -1 || b64_end != line + b64_len - 1) {
                        fprintf(stderr,
                            "read_peerinfo(); invalid master_pk\n");
                        free(bin);
                        ret = -13;
                    } else {
                        pi->master_pk_size = bin_len;
                        pi->master_pk = bin;
                    }
                }
                break;
            case 5:
                if (sscanf(line, "%"SCNu32, 
                        &pi->master_sequence_num) != 1) {
                    fprintf(stderr,
                        "read_peerinfo(); invalid master_sequence_num\n");
                    ret = -14;
                }
                break;
        }
    }

    if (s == -1 && nline < 5) {
        fprintf(stderr, "read_peerinfo(); invalid "UNILINK_PEERINFO"\n");
        ret = -15;
    }

    free(line);
    fclose(fp);
    return ret;
}

int     write_peerinfo(struct peerinfo *pi) {
    FILE    *fp;
    char    *b64_pk, *b64_master_pk;
    size_t  b64_pk_maxlen, b64_master_pk_maxlen;
    int     s;

    if (pi == NULL) {
        fprintf(stderr, "write_peerinfo(); pi == NULL\n");
        return -1;
    }

    fp = fopen(UNILINK_PEERINFO, "w");
    if (fp == NULL) {
        fprintf(stderr, "write_peerinfo(); fopen failed\n");
        return -2;
    }

    b64_pk_maxlen = sodium_base64_ENCODED_LEN(pi->pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_pk = malloc(b64_pk_maxlen);
    if (b64_pk == NULL) {
        fprintf(stderr, "write_peerinfo(); malloc failed\n");
        fclose(fp);
        return -3;
    }

    sodium_bin2base64(b64_pk, b64_pk_maxlen, pi->pk,
        pi->pk_size, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_master_pk_maxlen = sodium_base64_ENCODED_LEN(pi->master_pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);                        

    b64_master_pk = malloc(b64_master_pk_maxlen);
    if (b64_master_pk == NULL) {
        fprintf(stderr, "write_peerinfo(); malloc failed\n");
        fclose(fp);
        free(b64_pk);
        return -4;
    }

    sodium_bin2base64(b64_master_pk, b64_master_pk_maxlen,
        pi->master_pk, pi->master_pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    s = fprintf(fp,
            "%s\n"          /* port */
            "%s\n"          /* alg_pk */
            "%s\n"          /* pk (base64) */
            "%s\n"          /* master_alg_pk */
            "%s\n"          /* master_pk (base64) */
            "%"SCNu32"\n",  /* master_sequence_num */
            pi->port,
            pi->alg_pk,
            b64_pk,
            pi->master_alg_pk,
            b64_master_pk,
            pi->master_sequence_num);

    if (s < 0) {
        fprintf(stderr, "write_peerinfo(); fprintf failed\n");
        fclose(fp);
        free(b64_pk);
        free(b64_master_pk);
        return -5;
    }

    free(b64_pk);
    free(b64_master_pk);
    fclose(fp);
    return 0;
}

int     init_peerinfo(struct peerinfo *pi) {
    const char      *b64_end;

    if (pi == NULL) {
        fprintf(stderr, "init_peerinfo(); pi == NULL\n");
        return -1;
    }
 
    pi->port = strdup("0");
    if (pi->port == NULL) {
        fprintf(stderr, "init_peerinfo(); strdup failed\n");
        return -2;
    }

    pi->alg_pk = strdup("x25519");
    if (pi->alg_pk == NULL) {
        free(pi->port);
        return -3;
    }
   
    pi->pk = malloc(crypto_sign_PUBLICKEYBYTES);
    if (pk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->port);
        free(pi->alg_pk);
        return -4;
    }

    pi->sk = malloc(crypto_sign_SECRETKEYBYTES);
    if (sk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->pk);
        free(pi->port);
        free(pi->alg_pk);
        return -5;
    }

    crypto_sign_keypair(pk, sk);
    
    pi->master_alg_pk = strdup(UNILINK_MASTER_ALG_PK);
    if (pi->master_alg_pk == NULL) {
        fprintf(stderr, "init_peerinfo(); strdup failed\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        return -6;
    }

    pi->master_pk = malloc(strlen(UNILINK_MASTER_PK)/4*3+2);
    if (pi->master_pk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        free(pi->master_alg_pk);
        return -7;
    }

    if (sodium_base642bin(pi->master_pk, strlen(UNILINK_MASTER_PK)/4*3+2,
        UNILINK_MASTER_PK, strlen(UNILINK_MASTER_PK), NULL,
        &pi->master_pk_size, &b64_end) == -1
        || b64_end != line + strlen(UNILINK_MASTER_PK) - 1) {
        fprintf(stderr, "init_peerinfo(); invalid UNILINK_MASTER_PK\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        free(pi->master_alg_pk);
        free(pi->master_pk);
        return -8;
    }

    pi->master_sequence_num = 0;

    return 0;
}

void    free_peerinfo(struct peerinfo *pi) {
    if (pi != NULL) {
        free(pi->port);
        free(pi->alg_pk);
        free(pi->pk);
        free(pi->sk);
        free(pi->master_alg_pk);
        free(pi->master_pk);
    }
    free(pi);
}

int     main(void) {
    struct peerinfo pi;
    int             s;
    int             serv_fd;

    if (sodium_init() < 0) {
        fprintf(stderr, "main(); sodium_init() failed\n");
        return EXIT_FAILURE;
    }

    s = read_peerinfo(&pi);
    if (s < 0) {
        fprintf(stderr, "main(); read_peerinfo failed\n");
        return EXIT_FAILURE;
    }

    s = create_server(&serv_fd, pi.port);
    if (s < 0) {
        fprintf(stderr, "main(); create_server failed\n");
        return EXIT_FAILURE;
    }

    server_loop(serv_fd);

    return EXIT_SUCCESS;
}

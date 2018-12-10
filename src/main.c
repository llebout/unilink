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

/* static char *test_command =
"unilink\n"
"0\n"
"0\n"
"Greetings!\n"
"I am a member of the unilink network.\n"
"57\n"
"\n"
"\n\n\n\nThis is binary data that ends with the end of the packet."
;

static char *test2_command =
"\n\n\n\n\n\n\n\n1\n\n\n\n"
; */

int     main(void) {
    struct peerinfo         pi;
    int                     s, udp_fd, tcp_fd;
    struct sockaddr_storage addr;
    socklen_t               addrlen;
    char                    port[NI_MAXSERV];

    if (sodium_init() < 0) {
        fprintf(stderr, "main(); sodium_init failed\n");
        return EXIT_FAILURE;
    }

    /* (void)test2_command;
    printf("%ld\n", is_complete_command
        ((unsigned char *) test_command, strlen(test_command)));

    return EXIT_SUCCESS; */

    s = read_peerinfo(&pi);
    if (s < 0) {
        s = init_peerinfo(&pi);
        if (s < 0) {
            fprintf(stderr, "main(); init_peerinfo failed\n");
            return EXIT_FAILURE;
        }
        s = write_peerinfo(&pi);
        if (s < 0) {
            // Not a fatal error, possibly means the file system is readonly
            fprintf(stderr, "main(); write_peerinfo failed\n");
        }
    }

    s = create_udp_server(&udp_fd, pi.port);
    if (s < 0) {
        fprintf(stderr, "main(); create_udp_server failed\n");
        free_peerinfo(&pi);
        return EXIT_FAILURE;
    }

    /* patch peerinfo with system choosen port */
    if (strcmp(pi.port, "0") == 0) {
        addrlen = sizeof addr;
        s = getsockname(udp_fd, (struct sockaddr *) &addr, &addrlen);
        if (s == -1) {
            fprintf(stderr, "main(); getsockname failed\n");
            free_peerinfo(&pi);
            close(udp_fd);
            return EXIT_FAILURE;
        }

        s = getnameinfo((struct sockaddr *) &addr, addrlen, NULL, 0,
                port, sizeof port, NI_NUMERICSERV);
        if (s != 0) {
            fprintf(stderr, "main(); getnameinfo failed\n");
            free_peerinfo(&pi);
            close(udp_fd);
            return EXIT_FAILURE;
        }

        free(pi.port);
        pi.port = strdup(port);
        if (pi.port == NULL) {
            fprintf(stderr, "main(); strdup failed\n");
            free_peerinfo(&pi);
            close(udp_fd);
            return EXIT_FAILURE;
        }

        s = write_peerinfo(&pi);
        if (s < 0) {
            // Not a fatal error, possibly means the file system is readonly
            fprintf(stderr, "main(); write_peerinfo failed\n");
        }       
    }

    s = create_tcp_server(&tcp_fd, pi.port);
    if (s < 0) {
        fprintf(stderr, "main(); create_tcp_server failed\n");
        free_peerinfo(&pi);
        close(udp_fd);
        return EXIT_FAILURE;
    }

    printf("main(); bound port %s\n", pi.port);

    server_loop(udp_fd, tcp_fd);

    return EXIT_SUCCESS;
}

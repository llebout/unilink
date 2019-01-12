#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

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

LIST_HEAD(cmd_handlers, cmd_handler)
handler_que = LIST_HEAD_INITIALIZER(handler_que);

LIST_HEAD(cp_head, conn_pending)
cp_que = LIST_HEAD_INITIALIZER(cp_que);

LIST_HEAD(npi_head, netpeerinfo)
npi_que = LIST_HEAD_INITIALIZER(npi_que);

struct peerinfo g_pi;
char g_announce[65535];

int ping_handler(struct cmdinfo *ci, void **handler_data) {
  int s;
  static const char *ping_reply = "unilink\n"
                                  "0\n"
                                  "1\n"
                                  "Greetings!\n"
                                  "I am a member of the unilink network.\n"
                                  "0\n"
                                  "\n";

  (void)handler_data;
  if (ci->is_reply) {

  } else {
    if (ci->is_tcp) {
      s = send(ci->fd, ping_reply, strlen(ping_reply), 0);
      if (s == -1) {
        fprintf(stderr, "ping_handler(); send failed\n");
        return -1;
      }
      return 1;
    } else {
      s = sendto(ci->fd, ping_reply, strlen(ping_reply), 0,
                 (struct sockaddr *)&ci->sa, ci->sa_len);
      if (s == -1) {
        fprintf(stderr, "ping_handler(); sendto failed\n");
        return -2;
      }
    }
  }
  return 0;
}

int address_type(struct sockaddr_storage *sa, socklen_t sa_len) {
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;
  unsigned char *b;

  if (sa == NULL) {
    fprintf(stderr, "address_type(); sa == NULL\n");
    return -1;
  }
  if (sa->ss_family == AF_INET ||
      (sa->ss_family == AF_INET6 &&
       (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&sa)->sin6_addr) ||
        IN6_IS_ADDR_V4COMPAT(&((struct sockaddr_in6 *)&sa)->sin6_addr)))) {
    if (sa_len < sizeof *sin) {
      fprintf(stderr, "address_type(); sa_len < sizeof *sin\n");
      return -2;
    }
    if (sa->ss_family == AF_INET) {
      sin = (struct sockaddr_in *)sa;
      b = (unsigned char *)&sin->sin_addr;
    } else {
      if (sa_len < sizeof *sin6) {
        fprintf(stderr, "address_type(); sa_len < sizeof *sin6\n");
        return -3;
      }
      b = (sizeof(struct in6_addr) - sizeof(struct in_addr) +
           (unsigned char *)&((struct sockaddr_in6 *)&sa)->sin6_addr);
    }
    if (b[0] == 10 || // Private
        (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
        (b[0] == 192 && b[1] == 168) ||
        (b[0] == 169 && b[1] == 254) ||                       // Link local
        b[0] == 127 ||                                        // Loopback
        (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) || // Unspecified
        (b[0] == 255 && b[1] == 255 && b[2] == 255 &&
         b[3] == 255) ||                           // Broadcast
        (b[0] == 192 && b[1] == 0 && b[2] == 2) || // Documentation
        (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
        (b[0] == 203 && b[1] == 0 && b[2] == 113)) {
      return 1; // Locally routable
    } else {
      return 2; // Globally routable
    }
  } else if (sa->ss_family == AF_INET6) {
    if (sa_len < sizeof *sin6) {
      fprintf(stderr, "address_type(); sa_len < sizeof *sin6\n");
      return -4;
    }
    sin6 = (struct sockaddr_in6 *)sa;
    if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
        IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ||
        IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
        IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) ||
        IN6_IS_ADDR_MC_NODELOCAL(&sin6->sin6_addr) ||
        IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr) ||
        IN6_IS_ADDR_MC_SITELOCAL(&sin6->sin6_addr) ||
        IN6_IS_ADDR_MC_ORGLOCAL(&sin6->sin6_addr)) {
      return 1; // Locally routable
    } else {
      return 2; // Globally routable
    }
  } else {
    return -5;
  }
}

int announce_handler(struct cmdinfo *ci, void **handler_data) {
  int s, already;
  size_t n_line, bin_len;
  char **tmp_line;
  static unsigned char tmp_pk[crypto_sign_PUBLICKEYBYTES];
  struct netpeerinfo *npi, *npi2;

  (void)handler_data;
  for (n_line = 0, tmp_line = ci->lines; *tmp_line != NULL;
       ++tmp_line, ++n_line)
    ;
  if (ci->is_reply) {

  } else {
    if (n_line >= 3) {
      bin_len = 0;
      s = sodium_base642bin(tmp_pk, sizeof tmp_pk, ci->lines[2],
                            strlen(ci->lines[2]), NULL, (size_t *const)bin_len,
                            NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
      if (s < 0) {
        fprintf(stderr, "announce_handler(); sodium_base642bin failed\n");
        return -1;
      }
      npi = calloc(1, sizeof *npi);
      if (npi == NULL) {
        fprintf(stderr, "announce_handler(); calloc failed\n");
        return -2;
      }
      npi->address = calloc(NI_MAXHOST, sizeof(char));
      if (npi->address == NULL) {
        fprintf(stderr, "announce_handler(); calloc failed\n");
        free(npi);
        return -3;
      }
      npi->port = calloc(NI_MAXSERV, sizeof(char));
      if (npi->port == NULL) {
        fprintf(stderr, "announce_handler(); calloc failed\n");
        free(npi->address);
        free(npi);
        return -4;
      }
      npi->pk = calloc(bin_len, sizeof(unsigned char));
      if (npi->pk == NULL) {
        fprintf(stderr, "announce_handler(); calloc failed\n");
        free(npi->port);
        free(npi->address);
        free(npi);
        return -5;
      }
      s = getnameinfo((struct sockaddr *)&ci->sa, ci->sa_len, npi->address,
                      NI_MAXHOST, npi->port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
      if (s != 0) {
        free(npi->pk);
        free(npi->port);
        free(npi->address);
        free(npi);
        return -6;
      }
      memcpy(npi->pk, tmp_pk, bin_len);
      npi->pk_size = bin_len;
      npi->role = 0;

      already = 0;
      LIST_FOREACH(npi2, &npi_que, e) {
        if (strcmp(npi->address, npi2->address) == 0 &&
            strcmp(npi->port, npi2->port) == 0) {
          ++already;
          break;
        }
      }
      if (already && npi->pk_size == npi2->pk_size &&
          memcmp(
              npi->pk, npi2->pk,
              (npi->pk_size > npi2->pk_size ? npi2->pk_size : npi->pk_size))) {
        fprintf(stderr,
                "announce_handler(); peer with address %s and port %s found "
                "with different public key\n",
                npi->address, npi->port);
      }
      if (already) {
        free(npi->address);
        free(npi->port);
        free(npi->pk);
        free(npi);
      } else {
        LIST_INSERT_HEAD(&npi_que, npi, e);
      }
      return 1;
    }
  }
  return 0;
}

int main(void) {
  int s, udp_fd, tcp_fd;
  struct sockaddr_storage addr;
  socklen_t addrlen;
  char port[NI_MAXSERV];
  struct cmd_handler *handler;
  struct netpeerinfo *npi;
  size_t b64_pk_maxlen;
  char *b64_pk;

  if (sodium_init() < 0) {
    fprintf(stderr, "main(); sodium_init failed\n");
    return EXIT_FAILURE;
  }

  /* (void)test2_command;
  printf("%ld\n", is_complete_command
      ((unsigned char *) test_command, strlen(test_command)));

  return EXIT_SUCCESS; */

  s = read_peerinfo(&g_pi);
  if (s < 0) {
    s = init_peerinfo(&g_pi);
    if (s < 0) {
      fprintf(stderr, "main(); init_peerinfo failed\n");
      return EXIT_FAILURE;
    }
    s = write_peerinfo(&g_pi);
    if (s < 0) {
      // Not a fatal error, possibly means the file system is readonly
      fprintf(stderr, "main(); write_peerinfo failed\n");
    }
  }

  s = create_udp_server(&udp_fd, g_pi.port);
  if (s < 0) {
    fprintf(stderr, "main(); create_udp_server failed\n");
    free_peerinfo(&g_pi);
    return EXIT_FAILURE;
  }

  /* patch peerinfo with system choosen port */
  if (strcmp(g_pi.port, "0") == 0) {
    addrlen = sizeof addr;
    s = getsockname(udp_fd, (struct sockaddr *)&addr, &addrlen);
    if (s == -1) {
      fprintf(stderr, "main(); getsockname failed\n");
      free_peerinfo(&g_pi);
      close(udp_fd);
      return EXIT_FAILURE;
    }

    s = getnameinfo((struct sockaddr *)&addr, addrlen, NULL, 0, port,
                    sizeof port, NI_NUMERICSERV);
    if (s != 0) {
      fprintf(stderr, "main(); getnameinfo failed\n");
      free_peerinfo(&g_pi);
      close(udp_fd);
      return EXIT_FAILURE;
    }

    free(g_pi.port);
    g_pi.port = strdup(port);
    if (g_pi.port == NULL) {
      fprintf(stderr, "main(); strdup failed\n");
      free_peerinfo(&g_pi);
      close(udp_fd);
      return EXIT_FAILURE;
    }

    s = write_peerinfo(&g_pi);
    if (s < 0) {
      // Not a fatal error, possibly means the file system is readonly
      fprintf(stderr, "main(); write_peerinfo failed\n");
    }
  }

  b64_pk_maxlen = sodium_base64_ENCODED_LEN(
      g_pi.pk_size, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  b64_pk = calloc(1, b64_pk_maxlen);
  if (b64_pk == NULL) {
    free_peerinfo(&g_pi);
    close(udp_fd);
    return EXIT_FAILURE;
  }

  sodium_bin2base64(b64_pk, b64_pk_maxlen, g_pi.pk, g_pi.pk_size,
                    sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  s = snprintf(g_announce, sizeof g_announce,
               "unilink\n1\n0\n%s\n%s\n%s\n0\n\n", g_pi.port, g_pi.alg_pk,
               b64_pk);
  if (s < 0) {
    fprintf(stderr, "main(); snprintf failed\n");
    free_peerinfo(&g_pi);
    free(b64_pk);
    close(udp_fd);
    return EXIT_FAILURE;
  }

  s = create_tcp_server(&tcp_fd, g_pi.port);
  if (s < 0) {
    fprintf(stderr, "main(); create_tcp_server failed\n");
    free_peerinfo(&g_pi);
    free(b64_pk);
    close(udp_fd);
    return EXIT_FAILURE;
  }

  printf("main(); bound port %s\n", g_pi.port);

  LIST_INIT(&handler_que);

  handler = calloc(1, sizeof *handler);
  if (handler == NULL) {
    fprintf(stderr, "main(); calloc failed\n");
    return EXIT_FAILURE;
  }

  handler->type = CMD_PING;
  handler->f = &ping_handler;

  LIST_INSERT_HEAD(&handler_que, handler, e);

  LIST_INIT(&cp_que);
  LIST_INIT(&npi_que);

  npi = calloc(1, sizeof *npi);
  if (npi == NULL) {
    fprintf(stderr, "main(); calloc failed\n");
    return EXIT_FAILURE;
  }

  npi->address = "127.0.0.1";
  npi->port = "43756";
  LIST_INSERT_HEAD(&npi_que, npi, e);

  server_loop(udp_fd, tcp_fd);

  return EXIT_SUCCESS;
}

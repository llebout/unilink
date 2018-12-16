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

int ping_handler(struct cmdinfo *ci, void **handler_data) {
  int s;
  static const char *ping_reply = "unilink\n"
                                  "0\n"
                                  "0\n"
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

int main(void) {
  struct peerinfo pi;
  int s, udp_fd, tcp_fd;
  struct sockaddr_storage addr;
  socklen_t addrlen;
  char port[NI_MAXSERV];
  struct cmd_handler *handler;

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
    s = getsockname(udp_fd, (struct sockaddr *)&addr, &addrlen);
    if (s == -1) {
      fprintf(stderr, "main(); getsockname failed\n");
      free_peerinfo(&pi);
      close(udp_fd);
      return EXIT_FAILURE;
    }

    s = getnameinfo((struct sockaddr *)&addr, addrlen, NULL, 0, port,
                    sizeof port, NI_NUMERICSERV);
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

  LIST_INIT(&handler_que);

  handler = calloc(1, sizeof *handler);
  if (handler == NULL) {
    fprintf(stderr, "main(); calloc failed\n");
    return EXIT_FAILURE;
  }

  handler->type = CMD_PING;
  handler->f = &ping_handler;

  LIST_INSERT_HEAD(&handler_que, handler, e);

  server_loop(udp_fd, tcp_fd);

  return EXIT_SUCCESS;
}

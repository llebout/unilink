#ifndef UNILINK_H
#define UNILINK_H

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "../include/queue.h"

#define UNILINK_NETWORK_MAGIC "unilink"
#define UNILINK_PEERINFO "unilink_peerinfo"
#define UNILINK_PEERLIST "unilink_peerlist"

#define UNILINK_MASTER_ALG_PK "x25519"
#define UNILINK_MASTER_PK                                                      \
  "MCowBQYDK2VuAyEAgfQh7ke0sf6or3nod0DJGPTyV6LPD7z1YSa0MzwCdH4="

struct peerinfo {
  char *port;
  char *alg_pk;
  size_t pk_size;
  unsigned char *pk;
  size_t sk_size;
  unsigned char *sk;
  char *master_alg_pk;
  size_t master_pk_size;
  unsigned char *master_pk;
  uint32_t master_sequence_num;
};

int read_peerinfo(struct peerinfo *pi);
int write_peerinfo(struct peerinfo *pi);
int init_peerinfo(struct peerinfo *pi);
void free_peerinfo(struct peerinfo *pi);
int create_udp_server(int *udp_fd, const char *port);
int create_tcp_server(int *tcp_fd, const char *port);
int server_loop(int udp_fd, int tcp_fd);
ssize_t is_complete_command(unsigned char *buf, size_t size,
                            unsigned char **start_of_end);
time_t elapsed_seconds();

typedef enum e_cmdtype {
  CMD_PING = 0,
  CMD_ANNOUNCE = 1,
  CMD_ELECT = 2,
} cmdtype;

struct cmdinfo {
  struct sockaddr_storage sa;
  socklen_t sa_len;
  int is_tcp;
  int fd;
  uint32_t type;
  int is_reply;
  char **lines;
  size_t end_size;
  unsigned char *end;
};

/*  Example CMD_PING raw command data
 *
 *  unilink
 *  0
 *  0
 *  Greetings!
 *  I am a member of the unilink network.
 *  57
 *
 *  This is binary data that ends with the end of the packet.
 *
 *
 *  The above gives the following cmdinfo structure
 *
 *  struct cmdinfo {
 *      ... socket information ...
 *      type = CMD_PING,
 *      is_reply = FALSE,
 *      *lines[] => {
 *          "Greetings!",
 *          "I am a member of the unilink network.",
 *      },
 *      end_size = 57,
 *      end[] = "This is binary data that ends with the end of the packet.",
 *  }
 */

int parse_cmdinfo(unsigned char *buf, size_t size, unsigned char *start_of_end,
                  struct cmdinfo *ci);
void free_cmdinfo(struct cmdinfo *ci);

typedef int cmd_handler(struct cmdinfo *, void **);

struct cmd_handler {
  LIST_ENTRY(cmd_handler) e;
  uint32_t type;
  void *handler_data;
  cmd_handler *f;
};

struct fd_buffer {
  LIST_ENTRY(fd_buffer) e;
  time_t last_active;
  int fd;
  size_t size;
  unsigned char *buf;
};

struct conn_pending;

typedef int conn_cb(struct conn_pending *, void **);

struct conn_pending {
  LIST_ENTRY(conn_pending) e;
  int fd;
  int status;
  void *cb_data;
  conn_cb *f;
};

struct netpeerinfo {
  LIST_ENTRY(netpeerinfo) e;
  char *address;
  char *port;
  size_t pk_size;
  unsigned char *pk;
  int role;
};

struct pending_data {
  size_t size;
  unsigned char *buf;
};

int address_type(struct sockaddr *sa, socklen_t sa_len);

#endif

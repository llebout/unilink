#ifndef UNILINK_H
#define UNILINK_H

#include <netdb.h>
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

#define LOG_ERR(fmt, ...)                                                      \
  do {                                                                         \
    fprintf(stderr, "%s(..); " fmt "\n", __func__, __VA_ARGS__);               \
  } while (0);

struct net_buffer {
  size_t size;
  void *buf;
};

struct publickey {
  char *alg;
  size_t size;
  unsigned char *data;
};

struct unilink_peer {
  struct net_fd *nf;
  unsigned short port;
  struct publickey pk;
  int role;
};

struct net_context {
  size_t nfds;
  struct pollfd *fds;
  LIST_HEAD(net_fds, net_fd) fd_que;
  LIST_HEAD(net_cmds, cmd_handler) cmd_que;
};

struct unilink_peer;

struct net_fd;

typedef int on_tcp_connect(struct net_fd *, int connect_err);

struct net_tcp {
  int is_connected;
  int is_active;
  on_tcp_connect *cb;
};

struct net_addr {
  int type;
  char host[NI_MAXHOST];
  char port[NI_MAXSERV];
  socklen_t salen;
  struct sockaddr_storage sa;
};
struct net_fd {
  LIST_ENTRY(net_fd) e;
  struct unilink_peer *peer;
  int fd;
  struct net_addr addr;
  struct net_tcp tcp;
  struct net_buffer nbuf;
  LIST_HEAD(cmd_states, cmd_state) cmd_que;
};

struct net_context;

typedef int func_periodic_task(struct net_context *, void *);

struct periodic_task {
  LIST_ENTRY(periodic_task) e;
  time_t interval;
  time_t last_call;
  func_periodic_task *f;
};
typedef void free_handler_data(void *);

struct cmd_state {
  LIST_ENTRY(cmd_state) e;
  uint32_t channel;
  uint32_t type;
  void *handler_data;
  free_handler_data *free;
};

int grow_net_buffer(struct net_buffer *nb, const void *data, size_t size);
int shrink_start_net_buffer(struct net_buffer *nb, size_t n);
void free_net_buffer(struct net_buffer *nb);
int add_cmd_state(struct cmd_state *cs, uint32_t channel, uint32_t type,
                  void *handler_data);
int net_addr_from_sockaddr(struct net_addr *na, struct sockaddr_storage *sa,
                           socklen_t salen);
int net_addr_from_fd(struct net_addr *na, int fd);
int register_periodic_task(struct periodic_task *pt, func_periodic_task *f,
                           time_t interval);
int unregister_periodic_task(struct periodic_task *pt);
int net_context_add_fd(struct net_context *nc, struct net_fd **nf,
                       struct pollfd **pf, int fd);
int net_context_del_fd(struct net_context *nc, int fd);
int net_context_find_net_fd(struct net_context *nc, int fd, struct net_fd **nf);
int net_context_register_cmd(struct net_context *nc, cmd_handler *f,
                             uint32_t type);
int net_context_call_cmd(struct net_context *ctx, struct net_fd *nf,
                         struct cmdinfo *ci, int *cmd_err);
int net_context_net_fd_set_peer(struct net_fd *nf, struct unilink_peer *up);
int net_loop(int udp_servfd, int tcp_servfd);

int ping_handler(struct cmdinfo *ci, void **handler_data);

#endif

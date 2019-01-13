#include <search.h>
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

#include <poll.h>
#include <signal.h>

#include <inttypes.h>

#include <time.h>

#include <errno.h>

#include <sodium.h>

#include <queue.h>
#include <unilink.h>

#define LOG_ERR(fmt, ...)                                                      \
  do {                                                                         \
    fprintf(stderr, __func__ "(..); " fmt "\n", __VA_ARGS__);                  \
  } while (false);

struct net_buffer {
  size_t size;
  void *buf;
};

int grow_net_buffer(struct net_buffer *nb, const void *data, size_t size) {
  size_t new_size;
  void *p;

  if (nb == NULL) {
    LOG_ERR("nb == NULL", 0);
    return -1;
  }

  if (nb->buf == NULL)
    nb->size = 0;
  new_size = nb->size + size;

  if (new_size < nb->size) {
    LOG_ERR("new_size overflowed", 0);
    return -2;
  }

  p = realloc(nb->buf, nb->size + size);
  if (p == NULL) {
    LOG_ERR("realloc failed", 0);
    return -3;
  }
  nb->buf = p;

  memcpy((unsigned char *)nb->buf + nb->size, data, size);
  nb->size = new_size;
  return 0;
}

int shrink_start_net_buffer(struct net_buffer *nb, size_t n) {
  size_t new_size;
  void *p;

  if (nb == NULL) {
    LOG_ERR("nb == NULL", 0);
    return -1;
  }

  if (nb->buf == NULL)
    nb->size = 0;

  new_size = nb->size - n;

  if (new_size > nb->size) {
    LOG_ERR("new_size underflowed", 0);
    return -2;
  }

  memmove(nb->buf, (unsigned char *)nb->buf + n, nb->size - n);

  p = realloc(nb->buf, new_size);
  if (p == NULL) {
    LOG_ERR("realloc failed", 0);
    return -3;
  }
  nb->buf = p;

  nb->size = new_size;
  return 0;
}

void free_net_buffer(struct net_buffer *nb) { free(nb->buf); }

struct cmd_state {
  LIST_ENTRY(cmd_stack) e;
  uint32_t channel;
  uint32_t type;
  void *handler_data;
};

int add_cmd_state(struct cmd_state *cs, uint32_t channel, uint32_t type,
                  void *handler_data) {
  struct cmd_state *cs_new;

  if (cs == NULL) {
    LOG_ERR("cs == NULL", 0);
    return -1;
  }

  cs_new = calloc(1, sizeof *cs_new);
  if (cs_new == NULL) {
    LOG_ERR("calloc failed", 0);
    return -2;
  }

  cs_new->channel = channel;
  cs_new->type = type;
  cs_new->handler_data = handler_data;

  LIST_INSERT_AFTER(cs, cs_new, e);
  return 0;
}

struct net_tcp {
  int is_connected;
  int is_active;
};

struct net_addr {
  int type;
  char host[NI_MAXHOST];
  char port[NI_MAXSERV];
  socklen_t salen;
  struct sockaddr_storage sa;
};

int net_addr_from_sockaddr(struct net_addr *na, struct sockaddr_storage *sa,
                           socklen_t salen) {
  int s;

  if (na == NULL) {
    LOG_ERR("na == NULL", 0);
    return -1;
  }
  if (sa == NULL) {
    LOG_ERR("sa == NULL", 0);
    return -2;
  }

  s = getnameinfo((struct sockaddr *)sa, salen, na->host, sizeof na->host,
                  na->serv, sizeof na->serv, NI_NUMERICHOST | NI_NUMERICSERV);
  if (s != 0) {
    LOG_ERR("getnameinfo failed", 0);
    return -3;
  }

  na->type = address_type((struct sockaddr *)sa, salen);
  if (na->type < 0) {
    LOG_ERR("address_type failed", 0);
    return -4;
  }

  return 0;
}

int net_addr_from_host_port() {}

int net_addr_from_fd() {}

struct net_fd {
  LIST_ENTRY(net_fd) e;
  int fd;
  struct net_addr _addr;
  struct net_tcp tcp;
  struct net_buffer nbuf;
  LIST_HEAD(cmd_states, cmd_state) cmd_que;
};

struct net_context {
  size_t nfds;
  struct pollfd *fds;
  LIST_HEAD(net_fds, net_fd) fd_que;
};

void net_loop(int udp_servfd, int tcp_servfd) {}

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

#include "../include/queue.h"
#include "../include/unilink.h"

#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define LOG_ERR(fmt, ...)                                                      \
  do {                                                                         \
    fprintf(stderr, "%s(..); " fmt "\n", __func__, __VA_ARGS__);               \
  } while (0);

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

typedef void free_handler_data(void *);

struct cmd_state {
  LIST_ENTRY(cmd_state) e;
  uint32_t channel;
  uint32_t type;
  void *handler_data;
  free_handler_data *free;
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
                  na->port, sizeof na->port, NI_NUMERICHOST | NI_NUMERICSERV);
  if (s != 0) {
    LOG_ERR("getnameinfo failed", 0);
    return -3;
  }

  na->type = address_type((struct sockaddr *)sa, salen);
  if (na->type < 0) {
    LOG_ERR("address_type failed", 0);
    return -4;
  }

  na->sa = *sa;
  na->salen = salen;

  return 0;
}

int net_addr_from_fd(struct net_addr *na, int fd) {
  int s;

  if (na == NULL) {
    LOG_ERR("na == NULL", 0);
    return -1;
  }

  na->salen = sizeof na->sa;
  s = getsockname(fd, (struct sockaddr *)&na->sa, &na->salen);
  if (s != 0) {
    LOG_ERR("getsockname failed", 0);
    return -2;
  }

  s = net_addr_from_sockaddr(na, &na->sa, na->salen);
  if (s < 0) {
    LOG_ERR("net_addr_from_sockaddr failed", 0);
    return -3;
  }

  return 0;
}

struct net_fd {
  LIST_ENTRY(net_fd) e;
  int fd;
  struct net_addr addr;
  struct net_tcp tcp;
  struct net_buffer nbuf;
  LIST_HEAD(cmd_states, cmd_state) cmd_que;
};

struct net_context;

typedef int func_periodic_task(struct net_context *, void *);

struct periodic_task {
  LIST_ENTRY (periodic_task) e;
  time_t interval;
  time_t last_call;
  func_periodic_task *f;
};

int register_periodic_task(struct periodic_task *pt, func_periodic_task *f, time_t interval) {
  struct periodic_task *elem_pt;

  if (pt == NULL) {
    LOG_ERR("pt == NULL", 0);
    return -1;
  }

  if (f == NULL) {
    LOG_ERR ("f == NULL", 0);
    return -2;
  }

  elem_pt = calloc(1, sizeof *elem_pt);
  if (elem_pt == NULL) {
    LOG_ERR("calloc failed", 0);
    return -3;
  }

  elem_pt->interval = interval;
  elem_pt->f = f;

  LIST_INSERT_AFTER(pt, elem_pt, e);

  return 0;
}

int unregister_periodic_task(struct periodic_task *pt) {
  if (pt == NULL) {
    LOG_ERR("pt == NULL", 0);
    return -1;
  }

  LIST_REMOVE(pt, e);

  free(pt);

  return 0;
}

struct net_context {
  size_t nfds;
  struct pollfd *fds;
  LIST_HEAD(net_fds, net_fd) fd_que;
};

int net_context_add_fd(struct net_context *nc, struct net_fd **nf, int fd) {
  void *p;
  struct net_fd *elem_nf;

  if (nc == NULL) {
    LOG_ERR("nc == NULL", 0);
    return -1;
  }

  p = realloc(nc->fds, nc->nfds * (sizeof *nc->fds + 1));
  if (p == NULL) {
    LOG_ERR("p == NULL", 0);
    return -2;
  }

  elem_nf = calloc(1, sizeof *elem_nf);
  if (elem_nf == NULL) {
    LOG_ERR("calloc failed", 0);
    free(p);
    return -3;
  }

  nc->fds = p;
  memset(&nc->fds[nc->nfds], 0, sizeof *nc->fds);
  nc->fds[nc->nfds].fd = fd;
  ++nc->nfds;

  elem_nf->fd = fd;
  LIST_INSERT_HEAD(&nc->fd_que, elem_nf, e);

  if (nf != NULL) {
    *nf = elem_nf;
  }

  return 0;
}

int net_context_del_fd(struct net_context *nc, int fd) {
  size_t i, k;
  struct net_fd *elem_nf;
  struct cmd_state *elem_cs;

  if (nc == NULL) {
    LOG_ERR("nc == NULL", 0);
    return -1;
  }

  LIST_FOREACH(elem_nf, &nc->fd_que, e) {
    if (elem_nf->fd == fd) {
      LIST_REMOVE(elem_nf, e);
      break;
    }
  }

  for (i = 0; i < nc->nfds; ++i) {
    if (nc->fds[i].fd == fd) {
      --nc->nfds;
      for (k = i; k < nc->nfds; ++k) {
        memcpy(&nc->fds[k], &nc->fds[k + 1], sizeof *nc->fds);
      }
      break;
    }
  }

  free_net_buffer(&elem_nf->nbuf);

  while (!LIST_EMPTY(&elem_nf->cmd_que)) {
    elem_cs = LIST_FIRST(&elem_nf->cmd_que);
    LIST_REMOVE(elem_cs, e);
    elem_cs->free(elem_cs->handler_data);
    free(elem_cs);
  }

  free(elem_nf);

  return 0;
}

void net_loop(int udp_servfd, int tcp_servfd) {
  struct net_context ctx;

  (void)udp_servfd;
  (void)tcp_servfd;
  memset(&ctx, 0, sizeof ctx);
  LIST_INIT (&ctx.fd_que);

}

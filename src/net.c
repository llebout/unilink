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

int net_context_add_fd(struct net_context *nc, struct net_fd **nf, struct pollfd **pf, int fd) {
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
  if (pf != NULL) {
    *pf = &nc->fds[nc->nfds];
  }

  ++nc->nfds;

  elem_nf->fd = fd;
  LIST_INSERT_HEAD(&nc->fd_que, elem_nf, e);

  if (nf != NULL) {
    *nf = elem_nf;
  }

  return 0;
}

/*
 * We must break out of the poll loop after calling this function
 * to avoid corrupting the nfds counter.
 */

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

int net_context_find_net_fd(struct net_context *nc, int fd,
                            struct net_fd **nf) {
  struct net_fd *elem_nf;

  if (nc == NULL) {
    LOG_ERR("nc == NULL", 0);
    return -1;
  }

  if (nf == NULL) {
    LOG_ERR("nf == NULL", 0);
    return -2;
  }

  LIST_FOREACH(elem_nf, &nc->fd_que, e) {
    if (elem_nf->fd == fd) {
      *nf = elem_nf;
      break;
    }
  }

  return 0;
}

int net_loop(int udp_servfd, int tcp_servfd) {
  struct net_context ctx;
  struct net_fd *nf;
  struct pollfd *pf, *pf2;
  int s, accept_sock, connect_err;
  unsigned char *recv_buf;
  size_t i, recv_buf_size;
  ssize_t received_size, end_size;
  struct sockaddr_storage accept_sa;
  socklen_t accept_sa_len, optlen;
  unsigned char *start_of_end;

  memset(&ctx, 0, sizeof ctx);
  LIST_INIT (&ctx.fd_que);

  recv_buf_size = sysconf(_SC_PAGESIZE);
  recv_buf = calloc(1, recv_buf_size);
  if (recv_buf == NULL) {
    LOG_ERR("calloc failed", 0);
    return -1;
  }

  s = net_context_add_fd(&ctx, NULL, &pf, udp_servfd);
  if (s < 0) {
    LOG_ERR("net_context_add_fd failed", 0);
    return -2;
  }

  pf->events = POLLIN;

  s = net_context_add_fd(&ctx, NULL, &pf, tcp_servfd);
  if (s < 0) {
    LOG_ERR("net_context_add_fd failed", 0);
    return -3;
  }

  pf->events = POLLIN;

  while ((s = poll(ctx.fds, ctx.nfds, 1000)) != -1) {
    for (i = 0; i < ctx.nfds; ++i) {
      pf = &ctx.fds[i];

      if (pf->revents & POLLIN) {
        if (pf->fd == udp_servfd) {
          // Process UDP packet
        } else if (pf->fd == tcp_servfd) {
          accept_sa_len = sizeof accept_sa;
          accept_sock =
              accept(pf->fd, (struct sockaddr *)&accept_sa, &accept_sa_len);
          if (accept_sock == -1) {
            LOG_ERR("accept failed", 0);
            continue;
          }

          s = net_context_add_fd(&ctx, NULL, &pf2, pf->fd);
          if (s < 0) {
            LOG_ERR("net_context_add_fd failed", 0);
            close(accept_sock);
            continue;
          }
        } else {
          received_size = recv(pf->fd, recv_buf, recv_buf_size, 0);
          if (received_size == -1) {
            LOG_ERR("recv failed", 0);
            close(pf->fd);
            s = net_context_del_fd(&ctx, pf->fd);
            if (s < 0) {
              LOG_ERR("net_context_del_fd failed", 0);
            }
            break;
          }

          s = net_context_find_net_fd(&ctx, pf->fd, &nf);
          if (s < 0) {
            LOG_ERR("net_context_find_net_fd failed", 0);
            close(pf->fd);
            s = net_context_del_fd(&ctx, pf->fd);
            if (s < 0) {
              LOG_ERR("net_context_del_fd failed", 0);
            }
            break;
          }

          nf->tcp.is_active = 1;

          if (nf->nbuf.size == 0 &&
              (end_size = is_complete_command(recv_buf, received_size,
                                              &start_of_end)) > 0) {
            // Process complete command
            continue; // or break;
          }

          s = grow_net_buffer(&nf->nbuf, recv_buf, received_size);
          if (s < 0) {
            LOG_ERR("grow_net_buffer failed", 0);
            close(pf->fd);
            s = net_context_del_fd(&ctx, pf->fd);
            if (s < 0) {
              LOG_ERR("net_context_del_fd failed", 0);
            }
            break;
          }
        }
      } else if (pf->revents & POLLOUT) {
        optlen = sizeof connect_err;
        s = getsockopt(pf->fd, SOL_SOCKET, SO_ERROR, &connect_err, &optlen);
        if (s == -1) {
          LOG_ERR("getsockopt failed", 0);
          close(pf->fd);
          s = net_context_del_fd(&ctx, pf->fd);
          if (s < 0) {
            LOG_ERR("net_context_del_fd failed", 0);
          }
          break;
        }

        s = net_context_find_net_fd(&ctx, pf->fd, &nf);
        if (s < 0) {
          LOG_ERR("net_context_find_net_fd failed", 0);
          close(pf->fd);
          s = net_context_del_fd(&ctx, pf->fd);
          if (s < 0) {
            LOG_ERR("net_context_del_fd failed", 0);
          }
          break;
        }

        s = nf->tcp.cb(nf, connect_err);
        if (s < 0) {
          LOG_ERR("A TCP connect callback encountered an error", 0);
          close(pf->fd);
          s = net_context_del_fd(&ctx, pf->fd);
          if (s < 0) {
            LOG_ERR("net_context_del_fd failed", 0);
          }
        }
      }
    }
  }

  return 0;
}

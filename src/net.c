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
  if (p == NULL && new_size != 0) {
    LOG_ERR("realloc failed", 0);
    return -3;
  }
  nb->buf = p;

  nb->size = new_size;
  return 0;
}

void free_net_buffer(struct net_buffer *nb) { free(nb->buf); }

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

int net_context_register_cmd(struct net_context *nc, cmd_handler *f,
                             uint32_t type) {
  struct cmd_handler *elem_ch;

  if (nc == NULL) {
    LOG_ERR("nc == NULL", 0);
    return -1;
  }

  if (f == NULL) {
    LOG_ERR("f == NULL", 0);
    return -2;
  }

  elem_ch = calloc(1, sizeof *elem_ch);
  if (elem_ch == NULL) {
    LOG_ERR("calloc failed", 0);
    return -3;
  }

  elem_ch->type = type;
  elem_ch->f = f;

  LIST_INSERT_HEAD(&nc->cmd_que, elem_ch, e);

  return 0;
}

int net_context_call_cmd(struct net_context *ctx, struct net_fd *nf,
                         struct cmdinfo *ci, int *cmd_err) {
  struct cmd_handler *elem_ch;
  int s;

  if (nf == NULL) {
    LOG_ERR("nf == NULL", 0);
    return -1;
  }

  if (ci == NULL) {
    LOG_ERR("ci == NULL", 0);
    return -2;
  }

  LIST_FOREACH(elem_ch, &ctx->cmd_que, e) {
    if (elem_ch->type == ci->type) {
      s = (elem_ch->f)(ci, &elem_ch->handler_data);
      if (cmd_err) {
        *cmd_err = s;
      }
      return 0;
    }
  }

  LOG_ERR("No handler was found for type %d", ci->type);
  return -3;
}
int net_context_net_fd_set_peer(struct net_fd *nf, struct unilink_peer *up) {
  if (nf == NULL) {
    LOG_ERR("nf == NULL", 0);
    return -1;
  }

  if (up == NULL) {
    LOG_ERR("up == NULL", 0);
    return -2;
  }

  nf->peer = up;
  return 0;
}

int net_loop(int udp_servfd, int tcp_servfd) {
  struct net_context ctx;
  struct net_fd *nf;
  struct pollfd *pf, *pf2;
  int s, accept_sock, connect_err, cmd_err;
  unsigned char *recv_buf;
  size_t i, recv_buf_size;
  ssize_t received_size, msg_size;
  struct sockaddr_storage accept_sa;
  socklen_t accept_sa_len, optlen;
  unsigned char *start_of_end;
  struct cmdinfo ci;

  memset(&ctx, 0, sizeof ctx);
  LIST_INIT(&ctx.fd_que);
  LIST_INIT(&ctx.cmd_que);

  s = net_context_register_cmd(&ctx, ping_handler, CMD_PING);
  if (s < 0) {
    LOG_ERR("net_context_register_cmd failed", 0);
    return -1;
  }

  recv_buf_size = sysconf(_SC_PAGESIZE);
  recv_buf = calloc(1, recv_buf_size);
  if (recv_buf == NULL) {
    LOG_ERR("calloc failed", 0);
    return -2;
  }

  s = net_context_add_fd(&ctx, NULL, &pf, udp_servfd);
  if (s < 0) {
    LOG_ERR("net_context_add_fd failed", 0);
    return -3;
  }

  pf->events = POLLIN;

  s = net_context_add_fd(&ctx, NULL, &pf, tcp_servfd);
  if (s < 0) {
    LOG_ERR("net_context_add_fd failed", 0);
    return -4;
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

          s = net_context_add_fd(&ctx, &nf, &pf2, accept_sock);
          if (s < 0) {
            LOG_ERR("net_context_add_fd failed", 0);
            close(accept_sock);
            continue;
          }

          pf2->events = POLLIN;

          s = net_addr_from_sockaddr(&nf->addr, &accept_sa, accept_sa_len);
          if (s < 0) {
            LOG_ERR("net_addr_from_sockaddr", 0);
            close(accept_sock);
            s = net_context_del_fd(&ctx, accept_sock);
            if (s < 0) {
              LOG_ERR("net_context_del_fd failed", 0);
            }
            break;
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
          } else if (received_size == 0) {
            LOG_ERR("fd %d: Connection closed", pf->fd);
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

          ci.is_tcp = 1;
          ci.fd = pf->fd;
          memcpy(&ci.sa, &nf->addr.sa, sizeof nf->addr.sa);
          ci.sa_len = nf->addr.salen;

          if (nf->nbuf.size == 0 &&
              (msg_size = is_complete_command(recv_buf, received_size,
                                              &start_of_end)) > 0) {
            s = parse_cmdinfo(recv_buf, received_size, start_of_end, &ci);
            if (s < 0) {
              LOG_ERR("parse_cmdinfo failed", 0);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            s = net_context_call_cmd(&ctx, nf, &ci, &cmd_err);
            if (s < 0) {
              LOG_ERR("net_context_call_cmd failed", 0);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            if (cmd_err < 0) {
              LOG_ERR("handler for type %d failed", ci.type);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            continue;
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

          if ((msg_size = is_complete_command(nf->nbuf.buf, nf->nbuf.size,
                                              &start_of_end)) > 0) {
            s = parse_cmdinfo(nf->nbuf.buf, nf->nbuf.size, start_of_end, &ci);
            if (s < 0) {
              LOG_ERR("parse_cmdinfo failed", 0);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            s = net_context_call_cmd(&ctx, nf, &ci, &cmd_err);
            if (s < 0) {
              LOG_ERR("net_context_call_cmd failed", 0);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            if (cmd_err < 0) {
              LOG_ERR("handler for type %d failed", ci.type);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }

            s = shrink_start_net_buffer(&nf->nbuf, msg_size);
            if (s < 0) {
              LOG_ERR("shrink_start_net_buffer failed", 0);
              close(pf->fd);
              s = net_context_del_fd(&ctx, pf->fd);
              if (s < 0) {
                LOG_ERR("net_context_del_fd failed", 0);
              }
              break;
            }
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

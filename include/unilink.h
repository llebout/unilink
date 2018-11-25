#ifndef UNILINK_H
#define UNILINK_H

#include <stdint.h>

#define UNILINK_PEERINFO "unilink_peerinfo"

struct peerinfo {
    char            *port;
    char            *alg_pubkey;
    size_t          pubkey_size;
    unsigned char   *pubkey;
    char            *master_alg_pubkey;
    size_t          master_pubkey_size;
    unsigned char   *master_pubkey;
    uint32_t        master_sequence_num;
};

int     read_peerinfo(struct peerinfo *pi);
int     write_peerinfo(struct peerinfo *pi);
int     init_peerinfo(struct peerinfo *pi);
void    free_peerinfo(struct peerinfo *pi);
int     create_server(int *fd, const char *port);
void    server_loop(int fd);

#endif

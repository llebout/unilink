#ifndef UNILINK_H
#define UNILINK_H

#include <stdint.h>

#define UNILINK_PEERINFO "unilink_peerinfo"

#define UNILINK_MASTER_ALG_PK "x25519"
#define UNILINK_MASTER_PK "MCowBQYDK2VuAyEAgfQh7ke0sf6or3nod0DJGPTyV6LPD7z1YSa0MzwCdH4="

struct peerinfo {
    char            *port;
    char            *alg_pk;
    size_t          pk_size;
    unsigned char   *pk;
    unsigned char   *sk;
    char            *master_alg_pk;
    size_t          master_pk_size;
    unsigned char   *master_pk;
    uint32_t        master_sequence_num;
};

int     read_peerinfo(struct peerinfo *pi);
int     write_peerinfo(struct peerinfo *pi);
int     init_peerinfo(struct peerinfo *pi);
void    free_peerinfo(struct peerinfo *pi);
int     create_server(int *fd, const char *port);
void    server_loop(int fd);

#endif

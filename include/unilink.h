#ifndef UNILINK_H
#define UNILINK_H

#include <stdint.h>

#define UNILINK_NETWORK_MAGIC "unilink"
#define UNILINK_PEERINFO "unilink_peerinfo"
#define UNILINK_PEERLIST "unilink_peerlist"

#define UNILINK_MASTER_ALG_PK "x25519"
#define UNILINK_MASTER_PK "MCowBQYDK2VuAyEAgfQh7ke0sf6or3nod0DJGPTyV6LPD7z1YSa0MzwCdH4="

struct peerinfo {
    char            *port;
    char            *alg_pk;
    size_t          pk_size;
    unsigned char   *pk;
    size_t          sk_size;
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
int     create_udp_server(int *udp_fd, const char *port);
int     create_tcp_server(int *tcp_fd, const char *port);
int     server_loop(int udp_fd, int tcp_fd);

typedef enum e_cmdtype {
    CMD_PING = 0,
    CMD_ANNOUNCE = 1,
    CMD_ELECT = 2,
} cmdtype;

struct cmdinfo {
    uint32_t        type;
    int             is_reply;
    char            **lines;
    size_t          end_size;
    unsigned char   *end;
};

/*  Example CMD_PING raw command data
 *  
 *  unilink
 *  0
 *  0
 *  Greetings!
 *  I am a member of the unilink network.
 *
 *  This is binary data that ends with the end of the packet.
 *
 *
 *  The above gives the following cmdinfo structure
 *
 *  struct cmdinfo {
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

typedef int cmd_handler(struct cmdinfo *); 

struct cmd_handler_que {
    void        *forw;
    void        *back;
    cmd_handler *f;
};



#endif

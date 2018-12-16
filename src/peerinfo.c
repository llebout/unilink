#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <sodium.h>

#include <unilink.h>

int     read_peerinfo(struct peerinfo *pi) {
    FILE        *fp;
    int         nline, port, ret;
    char        *line;
    const char  *b64_end;
    void        *bin;
    size_t      n, bin_len, b64_len;
    ssize_t     s;

    if (pi == NULL) {
        fprintf(stderr, "read_peerinfo(); pi == NULL\n");
        return -1;
    }

    fp = fopen(UNILINK_PEERINFO, "r");
    if (fp == NULL) {
        fprintf(stderr, "read_peerinfo(); fopen failed\n");
        return -2;
    }

    ret = 0;
    for (line = NULL, n = 0, nline = 0;
                ret >= 0 && (s = getline(&line, &n, fp)) != -1; ++nline) {
        if (s == 0) {
            fprintf(stderr, "read_peerinfo(); empty line\n");
            ret = -3;
            break;
        }
        if (line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = 0;
        }
        switch (nline) {
            case 0:
                port = atoi(line);
                if (port > 0 && port < 65535) {
                    pi->port = strdup(line);
                    if (pi->port == NULL) {
                        fprintf(stderr,
                            "read_peerinfo(); port strdup failed\n");
                        ret = -4;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid port\n");
                    ret = -5;
                }
                break;
            case 1:
                if (strcmp(line, "x25519") == 0) {
                    pi->alg_pk = strdup(line);
                    if (pi->alg_pk == NULL) {
                        fprintf(stderr,
                            "read_peerinfo(); pk strdup failed\n");
                        ret = -6;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid alg_pk\n");
                    ret = -7;
                }
                break;
            case 2:
                b64_len = strlen(line);
                /*
                    allocates theoretical maximum decoded length,
                    wastes some space but reduces code complexity.
                */
                bin = malloc(b64_len/4*3+2);
                
                if (bin == NULL) {
                    fprintf(stderr,
                        "read_peerinfo(); bin malloc failed\n");
                    ret = -8;
                } else {
                    if (sodium_base642bin(
                            bin,
                            b64_len/4*3+2,
                            line,
                            b64_len,
                            NULL,
                            &bin_len,
                            &b64_end,
                            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
                        ) == -1) {
                        fprintf(stderr,
                            "read_peerinfo(); invalid pk\n");
                        free(bin);
                        ret = -9;
                    } else {
                        pi->pk_size = bin_len;
                        pi->pk = bin;
                    }
                }
                break;
            case 3:
                b64_len = strlen(line);
                /*
                    allocates theoretical maximum decoded length,
                    wastes some space but reduces code complexity.
                */
                bin = malloc(b64_len/4*3+2);
                
                if (bin == NULL) {
                    fprintf(stderr,
                        "read_peerinfo(); bin malloc failed\n");
                    ret = -10;
                } else {
                    if (sodium_base642bin(
                            bin,
                            b64_len/4*3+2,
                            line,
                            b64_len,
                            NULL,
                            &bin_len,
                            &b64_end,
                            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
                        ) == -1) {
                        fprintf(stderr,
                            "read_peerinfo(); invalid sk\n");
                        free(bin);
                        ret = -11;
                    } else {
                        pi->sk_size = bin_len;
                        pi->sk = bin;
                    }
                }
                break;
            case 4:
                if (strcmp(line, "x25519") == 0) {
                    pi->master_alg_pk = strdup(line);
                    if (pi->master_alg_pk == NULL) {
                        fprintf(
                            stderr,
                            "read_peerinfo(); master_pk strdup failed\n"
                        );
                        ret = -12;
                    }
                } else {
                    fprintf(stderr,
                        "read_peerinfo(); invalid master_alg_pk\n");
                    ret = -13;
                }
                break;
            case 5:
                b64_len = strlen(line);
                /*
                    allocates theoretical maximum decoded length,
                    wastes some space but reduces code complexity.
                */
                bin = malloc(b64_len/4*3+2);
                
                if (bin == NULL) {
                    fprintf(stderr,
                        "read_peerinfo(); bin malloc failed\n");
                    ret = -14;
                } else {
                    if (sodium_base642bin(
                            bin,
                            b64_len/4*3+2,
                            line,
                            b64_len,
                            NULL,
                            &bin_len,
                            &b64_end,
                            sodium_base64_VARIANT_ORIGINAL_NO_PADDING
                        ) == -1) {
                        fprintf(stderr,
                            "read_peerinfo(); invalid master_pk\n");
                        free(bin);
                        ret = -15;
                    } else {
                        pi->master_pk_size = bin_len;
                        pi->master_pk = bin;
                    }
                }
                break;
            case 6:
                if (sscanf(line, "%"SCNu32, 
                        &pi->master_sequence_num) != 1) {
                    fprintf(stderr,
                        "read_peerinfo(); invalid master_sequence_num\n");
                    ret = -16;
                }
                break;
        }
    }

    if (s == -1 && nline < 6) {
        fprintf(stderr, "read_peerinfo(); invalid "UNILINK_PEERINFO"\n");
        ret = -17;
    }

    free(line);
    fclose(fp);
    return ret;
}

int     write_peerinfo(struct peerinfo *pi) {
    FILE    *fp;
    char    *b64_pk, *b64_sk, *b64_master_pk;
    size_t  b64_pk_maxlen, b64_sk_maxlen, b64_master_pk_maxlen;
    int     s;

    if (pi == NULL) {
        fprintf(stderr, "write_peerinfo(); pi == NULL\n");
        return -1;
    }

    fp = fopen(UNILINK_PEERINFO, "w");
    if (fp == NULL) {
        fprintf(stderr, "write_peerinfo(); fopen failed\n");
        return -2;
    }

    b64_pk_maxlen = sodium_base64_ENCODED_LEN(pi->pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_pk = malloc(b64_pk_maxlen);
    if (b64_pk == NULL) {
        fprintf(stderr, "write_peerinfo(); malloc failed\n");
        fclose(fp);
        return -3;
    }

    sodium_bin2base64(b64_pk, b64_pk_maxlen, pi->pk,
        pi->pk_size, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_sk_maxlen = sodium_base64_ENCODED_LEN(pi->sk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_sk = malloc(b64_sk_maxlen);
    if (b64_sk == NULL) {
        fprintf(stderr, "write_peerinfo(); malloc failed\n");
        fclose(fp);
        return -4;
    }

    sodium_bin2base64(b64_sk, b64_sk_maxlen, pi->sk,
        pi->sk_size, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    b64_master_pk_maxlen = sodium_base64_ENCODED_LEN(pi->master_pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);                        

    b64_master_pk = malloc(b64_master_pk_maxlen);
    if (b64_master_pk == NULL) {
        fprintf(stderr, "write_peerinfo(); malloc failed\n");
        fclose(fp);
        free(b64_pk);
        return -5;
    }

    sodium_bin2base64(b64_master_pk, b64_master_pk_maxlen,
        pi->master_pk, pi->master_pk_size,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    s = fprintf(fp,
            "%s\n"         /* port */
            "%s\n"         /* alg_pk */
            "%s\n"         /* pk (base64) */
            "%s\n"         /* sk (base64) */
            "%s\n"         /* master_alg_pk */
            "%s\n"         /* master_pk (base64) */
            "%"SCNu32"\n", /* master_sequence_num */
            pi->port,
            pi->alg_pk,
            b64_pk,
            b64_sk,
            pi->master_alg_pk,
            b64_master_pk,
            pi->master_sequence_num);

    if (s < 0) {
        fprintf(stderr, "write_peerinfo(); fprintf failed\n");
        fclose(fp);
        free(b64_pk);
        free(b64_master_pk);
        return -6;
    }

    free(b64_pk);
    free(b64_master_pk);
    fclose(fp);
    return 0;
}

int     init_peerinfo(struct peerinfo *pi) {
    const char      *b64_end;

    if (pi == NULL) {
        fprintf(stderr, "init_peerinfo(); pi == NULL\n");
        return -1;
    }
 
    pi->port = strdup("0");
    if (pi->port == NULL) {
        fprintf(stderr, "init_peerinfo(); strdup failed\n");
        return -2;
    }

    pi->alg_pk = strdup("x25519");
    if (pi->alg_pk == NULL) {
        free(pi->port);
        return -3;
    }
   
    pi->pk = malloc(crypto_sign_PUBLICKEYBYTES);
    if (pi->pk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->port);
        free(pi->alg_pk);
        return -4;
    }

    pi->sk = malloc(crypto_sign_SECRETKEYBYTES);
    if (pi->sk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->pk);
        free(pi->port);
        free(pi->alg_pk);
        return -5;
    }

    pi->pk_size = crypto_sign_PUBLICKEYBYTES;
    pi->sk_size = crypto_sign_SECRETKEYBYTES;

    crypto_sign_keypair(pi->pk, pi->sk);
    
    pi->master_alg_pk = strdup(UNILINK_MASTER_ALG_PK);
    if (pi->master_alg_pk == NULL) {
        fprintf(stderr, "init_peerinfo(); strdup failed\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        return -6;
    }

    pi->master_pk = malloc(strlen(UNILINK_MASTER_PK)/4*3+2);
    if (pi->master_pk == NULL) {
        fprintf(stderr, "init_peerinfo(); malloc failed\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        free(pi->master_alg_pk);
        return -7;
    }

    if (sodium_base642bin(
        pi->master_pk,
        strlen(UNILINK_MASTER_PK)/4*3+2,
        UNILINK_MASTER_PK,
        strlen(UNILINK_MASTER_PK),
        NULL,
        &pi->master_pk_size,
        &b64_end,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING
        ) == -1) {
        fprintf(stderr,
            "init_peerinfo(); invalid UNILINK_MASTER_PK\n");
        free(pi->pk);
        free(pi->sk);
        free(pi->port);
        free(pi->alg_pk);
        free(pi->master_alg_pk);
        free(pi->master_pk);
        return -8;
    }

    pi->master_sequence_num = 0;

    return 0;
}

void    free_peerinfo(struct peerinfo *pi) {
    if (pi != NULL) {
        free(pi->port);
        free(pi->alg_pk);
        free(pi->pk);
        free(pi->sk);
        free(pi->master_alg_pk);
        free(pi->master_pk);
    }
}

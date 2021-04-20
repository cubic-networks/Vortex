#ifndef _VORTEX_H
#define _VORTEX_H

#define VORTEX_MAX_CRED_LEN 1024    // default credential length 1024
#define VORTEX_MAX_TIMEOUT  300     // default timeout after 5 minutes, translate to 300 seconds

#include <sys/types.h>

typedef enum {
    ENCRYPT = 0,
    DECRYPT = 1,

    NUM_CRYPTO_FUNCTION_CNT
} crypto_function;

typedef struct vortex_node_s {
    int signature;
    unsigned char key[VORTEX_MAX_CRED_LEN];
    int size;
    unsigned int time_out;
    struct vortex_node_s * next;
} vortex_node;

typedef struct vortex_instance_s {
    unsigned char nounce[VORTEX_MAX_CRED_LEN];
    unsigned int node_cnt;
    vortex_node * head;
} vortex_instance;

void vortex_init();
void vortex_assign(int signature, int key_len, unsigned char * key);
void vortex_resign(int signature);
ssize_t vortex_crypto(int signature, unsigned char * input, ssize_t input_len, unsigned char * output, crypto_function selection);
void vortex_reclaim();
ssize_t vortex_retrieve_key(int signature, unsigned char ** key_out);

#endif

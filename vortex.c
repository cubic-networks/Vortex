#include "vortex.h"
#include "Package.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static vortex_instance * vort;
static int vort_init = 0;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv)) {
        handleErrors();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void crypto(unsigned char * input, int input_len, unsigned char * output, int output_len) {
#ifdef VORTEX_DEBUG
    int idx;
    printf("%s: \n", __FUNCTION__);
    printf("\tinput: %d %d\n\t", input_len, output_len);
    for (idx = 0; idx < input_len; idx++) {
        printf("%02x", input[idx]);
    }
    printf("\n");
#endif
    do_crypto(1088, input, input_len, output, output_len);
}

uint64_t string_to_mac(const char * mac) {
    union {
        unsigned char a[6];
        uint64_t val;
    } ret;
    ret.val = 0;
    int rc = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    ret.a, ret.a + 1, ret.a + 2, ret.a + 3, ret.a + 4, ret.a + 5);

    if (rc != 6)
        return 0;
    else {

        return ret.val;
    }
}

int sanity_check(unsigned char * input, int input_len) {
    return 1;
}

void vortex_init() {
    if (!vort_init) {
        // creat instance
        vort = (vortex_instance *) malloc(sizeof(vortex_instance));
        vort->head = NULL;
        vort->node_cnt = 0;
        crypto((unsigned char *) "", 1, vort->nounce, VORTEX_MAX_CRED_LEN);

        vort_init = 1;
    }
}

void vortex_reclaim() {
    vortex_node * cur = vort->head;
    
    if (vort_init) {
        if (vort->node_cnt) {
            int idx = 0;
            for (idx = 0; idx < vort->node_cnt; ++idx) {
                vortex_node * tmp = cur;
                cur = cur->next;

                // clear all nodes related
                free(tmp);
            }
        }

        // clear existing instance
        free(vort);

        vort_init = 0;
    }
}

void vortex_config_path(
        int sock_fd,
        const char * local_ip,
        const char * remote_ip,
        const char * local_mac,
        const char * remote_mac) {
    if (vort_init) {
        vortex_node * itr = vort->head, * prev = NULL;
        unsigned char key_input[24];
        uint64_t mac_val;

#ifdef VORTEX_DEBUG
        printf("%s(%s)[%d] %d %s %s %s %s\n",
                __FUNCTION__, __FILE__, __LINE__,
                sock_fd, local_ip, remote_ip, local_mac, remote_mac);
        fflush(stdout);
#endif

        // convert ip and mac [li|lm|ri|rm]
        inet_pton(AF_INET, local_ip, key_input);
        mac_val = string_to_mac(local_mac);
        memcpy(key_input + 8, &mac_val, sizeof(uint64_t));
        inet_pton(AF_INET, remote_ip, key_input + 4);
        mac_val = string_to_mac(remote_mac);
        memcpy(key_input + 14, &mac_val, sizeof(uint64_t));

#ifdef VORTEX_DEBUG
        printf("key_input %s\n", key_input);
        fflush(stdout);
#endif

        if (vort->head == NULL) {
            vort->head = (vortex_node *) malloc(sizeof(vortex_node));
            vort->node_cnt ++;
            
            itr = vort->head;
            itr->sock_fd = sock_fd;
            itr->time_out = VORTEX_MAX_TIMEOUT;
            crypto(key_input, 20, itr->key, VORTEX_MAX_CRED_LEN);
            itr->next = NULL;
        } else {
            while (itr != NULL) {
                if (itr->sock_fd == sock_fd)
                    break;
                else {
                    prev = itr;
                    itr = itr->next;
                }
            }

            if (itr == NULL) {
#ifdef VORTEX_DEBUG
                printf("create new path\n");
#endif
                itr = (vortex_node *) malloc(sizeof(vortex_node));
                if (prev)
                    prev->next = itr;
                vort->node_cnt++;
            }

            itr->sock_fd = sock_fd;
            itr->time_out = VORTEX_MAX_TIMEOUT;
            crypto(key_input, 20, itr->key, VORTEX_MAX_CRED_LEN);
            itr->next = NULL;
        }
    }
}

void vortex_deconfig_path(int sockfd) {
    if (vort_init) {
        vortex_node * itr = vort->head, * prev = NULL;

        while(itr != NULL) {
            if (itr->sock_fd == sockfd)
                break;
            else {
                prev = itr;
                itr = itr->next;
            }
        }

        if (itr != NULL) {
            if (prev)
                prev->next = itr->next;

            vort->node_cnt--;
            free(itr);
        }
    }
}

ssize_t vortex_crypto(
        int sock_fd,
        unsigned char * input,
        ssize_t input_len,
        unsigned char * output,
        crypto_function selection) {
    ssize_t ret_len = -1;
    unsigned char * temp = NULL;
    int idx;

    // following section is retrieving the path information
    if (!vort_init) {
        printf("vortex system not initialized\n");
        return ret_len;
    } else if ((selection == DECRYPT) && (input_len < 16)) {
        // AES is 128 bit block cipher, so the minimum data length is 16 bytes = 128 bits.
        // When decrypting, cipher text should never be less than 16 bytes. Otherwise,
        // data must have been truncated.
        printf("not enough data to decrypt.\n");
        return ret_len;
    } else if ((selection == ENCRYPT) && (input_len < 16)) {
        // input length is not enough, pad it with 0s
        temp = (unsigned char *) malloc(16);
        memset(temp, 0, 16);
        memcpy(temp, input, input_len);
        input_len = 16;
    }

    vortex_node * itr = vort->head;

#ifdef VORTEX_DEBUG
    printf("%s(%s): %p %d %d %d\n\t",
            __FUNCTION__, __FILE__, itr, sock_fd, input_len, selection);
    for (idx = 0; idx < input_len; ++idx) {
        printf("%02x", input[idx]);
    }
    printf("\n");
    if (temp != NULL) {
        printf("\t");
        for (idx = 0; idx < 16; ++idx) {
            printf("%02x", temp[idx]);
        }
        printf("\n");
    }
#endif

    while(itr != NULL) {
        if (itr->sock_fd == sock_fd)
            break;
        else
            itr = itr->next;
    }

    // in case the sock node is not here
    if (itr == NULL) {
        printf("path not configured properly\n");
        return ret_len;
    }

    // start actual encryption or decryption based on selection
#ifdef VORTEX_DEBUG
    printf("\nenc_key\n\t");
    for (idx = 0; idx < 1024; ++idx)
        printf("%02x", (itr->key)[idx]);
    printf("\nnounce\n\t");
    for (idx = 0; idx < 1024; ++idx)
        printf("%02x", (vort->nounce)[idx]);
    printf("\n");
#endif

    switch(selection) {
        case ENCRYPT:
            ret_len = encrypt((temp == NULL) ? input : temp, input_len, itr->key, vort->nounce, output);
            break;
        case DECRYPT:
            ret_len = decrypt(input, input_len, itr->key, vort->nounce, output);
            break;
        case NUM_CRYPTO_FUNCTION_CNT:
        default:
            ret_len = 0;
            break;
    }

    if (temp != NULL)
        free(temp);
    return ret_len;
}

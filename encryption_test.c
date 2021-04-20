#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include "vortex.h"

static char test_input[1024];
static unsigned char output[1024];
static int output_len = 0;
static int input_len = 0;

void usage() {
    printf("\n");
    printf("Cubic Netwokrs Inc. All Rights Reserved.\n");
    printf("Vortex Message Encoding Test.\n");
    printf("%s %s\n", __DATE__, __TIME__);
    printf("\n################################################\n");
    printf("\nCLI syntax\n");
    printf("------------------------------------\n");
    printf("./enc_test <option list> [list of ingredience seperated with space]\n");
    printf("\nCLI available options\n");
    printf("------------------------------------\n");
    printf("-h\tprint this help message.\n");
    printf("-v\tverbose mode. print more information, exspecially regarding encryption keys.\n");
    printf("-t\ttext input\n");
    printf("-s\ttext size\n");
    
    printf("\n");
}

int main (int argc, char * argv[]) {
    int idx, vflag = 0, c, enc_len = 0, tflag = 0;
    unsigned char enc_list[1024];

    while((c = getopt(argc, argv, "s:t:vh")) != -1) {
        switch (c) {
            case 't':
                tflag = 1;
                strcpy(test_input, optarg);
                break;
            case 's':
                sscanf(optarg, "%d", &input_len);
                break;
            case 'h':
                usage();
                exit(1);
            case 'v':
                vflag = 1;
                break;
            case '?':
                if ((optopt == 't') ||
                    (optopt == 's'))
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
                return 1;
            default:
                abort();
        }
    }

    if (!tflag) {
        strcpy(test_input, "This is a test message.");
    }

    if (!input_len) {
        input_len = strlen(test_input);
    }

    memset(enc_list, 0, 1024);
    for (idx = optind; idx < argc; ++idx) {
        sprintf((char *) enc_list, "%s%s", enc_list, argv[idx]);
        enc_len += strlen(argv[idx]);
    }

    printf("vortex init.\n");
    vortex_init();

    vortex_assign(0, enc_len, (enc_len == 0) ? (unsigned char *) "" : enc_list);

    if (vflag) {
        unsigned char key[1024];
        int key_size = 0, key_idx = 0;

        key_size = (int) vortex_retrieve_key(0, (unsigned char **) &key);
        
        printf("encryption key constructed from token: %s\n", enc_list);
        printf("encryption key size is %d\n", key_size);
        printf("key: 0x");
        for (; key_idx < key_size; ++key_idx) {
            printf("%02x", key[key_idx]);
        }
        printf("\n");
    }
    
    if ((output_len = vortex_crypto(0, (unsigned char *) test_input, input_len,
                               output,  ENCRYPT)) == -1) {
        printf("please review vortex configuration, make sure the encryption path is assigned properly.\n");
        return -1;
    }

    output[output_len] = '\0';

    printf("input \"%s\"(%d), encrypted %d bytes to\n\t",
            test_input, input_len,
            output_len);
    for (idx = 0; idx < output_len; ++idx) {
        printf("%02x", output[idx]);
    }
    printf("\n");

    printf("decrypting\n");
    output_len = vortex_crypto(0, output, output_len, output, DECRYPT);

    printf("decryption %d bytes to \"%s\"\n",
            output_len, output);

    vortex_resign(0);
    vortex_reclaim();
}

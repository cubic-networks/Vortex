#include "vortex.h"
#include <string.h>
#include <stdio.h>

static char test_input[1024];
static unsigned char output[1024];
static int output_len = 0;
static int input_len = 0;

int main (int argc, char * argv[]) {
    int idx;
    printf("input arguments: %d\n", argc);

    if (argc == 1) {
        strcpy(test_input, "This is a test message");
        input_len = strlen(test_input);
    } else if (argc == 2) {
        strcpy(test_input, argv[1]);
        input_len = strlen(test_input);
    } else if (argc >= 3) {
        input_len = atoi(argv[2]);
        memcpy(test_input, argv[1], input_len);
    }

    printf("vortex init.\n");
    vortex_init();

    printf("configure path 192.168.3.1, to 192.168.3.2\n");
    vortex_config_path(0, "192.168.3.1", "192.168.3.2", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff");

    printf("encrypting\n");
    output_len = vortex_crypto(0, (unsigned char *) test_input, input_len,
                               output,  ENCRYPT);
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

    vortex_deconfig_path(0);
    vortex_reclaim();
}

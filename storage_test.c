#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "vortex.h"

enum {
    ENCRYPTION,
    DECRYPTION,

    NUM_CRYPTO_MODE
};

void usage() {
    printf("\n");
    printf("Cubic Netwokrs Inc. All Rights Reserved.\n");
    printf("Vault File Encyption Test.\n");
    printf("%s %s\n", __DATE__, __TIME__);
    printf("\n################################################\n");
    printf("\nCLI syntax\n");
    printf("------------------------------------\n");
    printf("./vault_test <option list> [list of ingredience seperated with space]\n");
    printf("\nCLI available options.\n");
    printf("------------------------------------\n");
    printf("-h\tPrint this help message.\n");
    printf("-v\tVerbose mode. Print more information, exspecially regarding encryption keys.\n");
    printf("-f\tInput file name\t\t"); printf("\033[1;33m"); printf("[Mandatory]\n"); printf("\033[0m");
    printf("-s\tInput file size\n");
    printf("-o\tOutput file name\n");
    printf("-m\tCrypto mode\t\t"); printf("\033[1;33m"); printf("[Mandatory]\n"); printf("\033[0m"); printf("\t0 for encryption, 1 for decryption. Default is encryption.");
    
    printf("\n");
}

int main (int argc, char * argv[]) {
    int64_t input_len = 0;
    int idx, c, enc_len = 0, verbose = 0, o_tag = 0, f_tag = 0, crypto_mode = 0;
    size_t output_len = 0;
    unsigned char enc_list[1024], in_buff[1024], out_buff[1024];
    char input_file[1024], output_file[1024];
    FILE * in_fp, * out_fp;

    while((c = getopt(argc, argv, "f:s:o:hvm:")) != -1) {
        switch (c) {
            case 'v':
                verbose = 1;
                break;
            case 'f':
                f_tag = 1;
                strcpy(input_file, optarg);
                if (access(input_file, F_OK) != 0) {
                    fprintf(stderr, "File %s does not exist. Please check input.\n", input_file);
                    return 1;
                }
                break;
            case 'o':
                o_tag = 1;
                strcpy(output_file, optarg);
                break;
            case 's':
                sscanf(optarg, "%lu", &input_len);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'm':
                sscanf(optarg, "%d", &crypto_mode);
                if ((crypto_mode != ENCRYPT) &&
                    (crypto_mode != DECRYPT)) {
                    fprintf(stderr, "Option -m can only take 0 or 1 as input. 0 for Encryption mode and 1 for Decryption mode. %s - %d\n", optarg, crypto_mode);
                    return 1;
                }
                break;
            case '?':
                if ((optopt == 'f') ||
                    (optopt == 'o') ||
                    (optopt == 's') ||
                    (optopt == 'm'))
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

    if (!f_tag) {
        fprintf(stderr, "An input file is REQUIRED for this test. Please checked usage message.\n");
        usage();
        exit(EXIT_SUCCESS);
    } else {
        struct stat f_st;
        if (stat(input_file, &f_st) == 0) {
            if ((input_len == 0) ||
                (input_len > (int64_t) f_st.st_size)) {
                input_len = (int64_t) f_st.st_size;
            }
        }
    }

    if (verbose)
        printf("input file name %s size %lu\n", input_file, input_len);

    if (!o_tag) {
        sprintf(output_file, "vort_stor_%s_out.vort", (crypto_mode == ENCRYPT) ? "enc" : "dec");
    }

    if (verbose)
        printf("output file name %s\n", output_file);

    // open input file
    if ((in_fp = fopen(input_file, "rb")) == NULL) {
        // file open fail
        fprintf(stderr, "input file open failed.\n");
        return 1;
    } else if (verbose) {
        printf("input file location: %p\n", in_fp);
    }

    // open output file
    if ((out_fp = fopen(output_file, "wb+")) == NULL) {
        // file open fail
        fprintf(stderr, "output file open failed.\n");
        return 1;
    }

    // generate extra ingress info
    for (idx = optind; idx < argc; ++idx) {
        sprintf((char *) enc_list, "%s%s", enc_list, argv[idx]);
        enc_len += strlen(argv[idx]);
    }

    /* start vortex sequences */
    if (verbose)
        printf("vortex init.\n");
    // init
    vortex_init();

    // calcualte encryption key
    if (verbose)
        printf("vortex_assign, %d %s\n", enc_len, enc_list);
    vortex_assign(0, enc_len, (enc_len == 0) ? (unsigned char *) "" : enc_list);

    // read file in 1K block and encrypt, write to output file.
    if (verbose)
        printf("start %s with 1K block size.\n", (crypto_mode == 0) ? "encrypting" : "decrypting");
    while (input_len != 0) {
        static size_t res = 0, out_enc_len = 0;
        static size_t rd_len = 0;
        rd_len = (input_len > sizeof(in_buff)) ? sizeof(in_buff) : input_len;
        if (in_fp != NULL)
            res = fread(in_buff, 1, rd_len, in_fp);
        else
            goto ERROR_EXIT;

        if (verbose)
            printf("[rest file size %lu]\t\tread from file: %lu bytes\n", input_len, rd_len);

        if (res != rd_len) {
            fprintf(stderr, "file read error.\n");
            goto ERROR_EXIT;
        } else {
            input_len -= res;
            if ((out_enc_len = vortex_crypto(0,
                                             (unsigned char *) in_buff,
                                             res,
                                             out_buff,
                                             crypto_mode)) == -1) {
                printf("please review vortex configuration, make sure the encryption path is assigned properly.\n");
                return -1;
            }

            if (out_fp != NULL)
                res = fwrite(out_buff, sizeof(unsigned char), out_enc_len, out_fp);
            else
                goto ERROR_EXIT;

            if (res != out_enc_len) {
                fprintf(stderr, "file write error.\n");
                goto ERROR_EXIT;
            } else {
                output_len += res;
            }

            if (verbose)
                printf("[output file size %lu]\twrite to file: %lu byte\n", output_len, out_enc_len);
        }
    }

    goto EXIT;

ERROR_EXIT:
    fprintf(stderr, "operation failed. please remove the output file manually and retry.\n");

EXIT:
    fclose(in_fp);
    fclose(out_fp);

    vortex_resign(0);
    vortex_reclaim();
}

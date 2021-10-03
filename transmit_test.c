#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <errno.h>

#include "vortex.h"

#define DEFAULT_MSG "This is a test message"
#define DEFAULT_PORT 1109


typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_size;
    int sock_fd;
    unsigned char key_eng[1024];
    int enc_len;
    int vflag;
    int client_idx;
} server_arg_t;

void usage() {
    printf("\n");
    printf("Cubic Netwokrs Inc. All Rights Reserved.\n");
    printf("Vortex System Test.\n");
    printf("%s %s\n", __DATE__, __TIME__);
    printf("\n################################################\n");
    printf("\nCLI syntax\n");
    printf("------------------------------------\n");
    printf("./enc_test <option list> [list of ingredience seperated with space]\n");
    printf("\nCLI available options\n");
    printf("------------------------------------\n");
    printf("-h or --help\n\tprint this help message.\n");
    printf("-v or --verbose\n\tverbose mode. print more information, exspecially regarding encryption keys.\n");
    printf("-l or --local\n\tflags system to run in local mode, with Unix Socket\n");
    printf("\n");
    printf("--server\n\tflags system to run as message server. mutually exclusive with client mode.\n");
    printf("--client\n\tflags system to run as message client. mutually exclusive with server mode.\n");
    printf("--srv-ip\n\tsource ip address to be used.\n");
    printf("--idx\n\tthe client index used for individual pathway designation. part of the encryption key calculation. required for client mode.\n");
    
    printf("\n");
}

void * serverThread(void * arg) {
    // received information
    int client_sock = ((server_arg_t *) arg)->sock_fd;
    int enc_len = ((server_arg_t *) arg)->enc_len;
    unsigned char * enc_list = ((server_arg_t *) arg)->key_eng;
    int vflag = ((server_arg_t *) arg)->vflag;
    int client_idx = ((server_arg_t *) arg)->client_idx;

    // local buffers and arguments
    char buff[128];
    int n, idx;
    int seq = 0;
    unsigned char output[1024];
    int output_len = 0;

    if (vflag) {
        printf("entering server thread with new sock id %d\n", client_sock);
        printf("using string \"%s\"[%d] for encryption key generation.\n", enc_list, enc_len);
    }

    vortex_assign(client_sock, enc_len, (enc_len == 0) ? (unsigned char *) "" : (unsigned char *) enc_list);
    if (vflag) {
        unsigned char key[1024];
        int key_size = 0, key_idx = 0;

        key_size = (int) vortex_retrieve_key(client_sock, (unsigned char **) &key);
        
        printf("encryption key constructed from token: %s\n", enc_list);
        printf("encryption key size is %d\n", key_size);
        printf("key: 0x");
        for (; key_idx < key_size; ++key_idx) {
            printf("%02x", key[key_idx]);
        }
        printf("\n");
    }

    bzero (buff, 128);

    while ((n = read(client_sock, buff ,sizeof(buff))) > 0) {
        bzero (output, sizeof(output));

        if (vflag)
            printf("decrypting %d bytes data received.\n", n);
        output_len = vortex_crypto(client_sock, (unsigned char *) buff, n, output, DECRYPT);

        if (vflag)
            printf("decryption %d bytes to \"%s\"\n", output_len, (char *) output);
        printf("From client %d: %s\n", client_idx, output);

        if (strncmp("exit", output, 4) == 0) {
            printf("Server thread Exit...\n");
            break;
        } else {
            bzero(buff, 128);
            bzero(output, sizeof(output));
            sprintf(buff, "Server message to Client %d: Message sequence %d\n", client_idx, seq++);
            n = strlen(buff);

            if ((output_len = vortex_crypto(client_sock, (unsigned char *) buff, n, output, ENCRYPT)) == -1) {
                printf("please review vortex configuration, make sure the encryption path is assigned properly.\n");
                break;
            }

            if (vflag) {
	            printf("input \"%s\"(%d), encrypted %d bytes to\n\t",
                        buff, n, output_len);
                for (idx = 0; idx < output_len; ++idx)
                    printf("%02x", output[idx]);
                printf("\n");
            }

            write(client_sock, output, output_len);
        }

        bzero(buff, 128);
    }

    close(client_sock);
    pthread_exit(NULL);
}

int main (int argc, char * argv[]) {
    int idx, c, enc_len = 0, server_flag = 0, client_flag = 0, mode_set = 0;
    static int vflag = 0, local_mode = 0, client_idx = 0;
    unsigned char server_ip[16], enc_list[1024];
    struct sockaddr_in addr;
    int sock;

    unsigned char output[1024];
    int output_len = 0;

    memset(&server_ip, 0, sizeof(server_ip));
    static struct option long_options[] = {
        /* Options that set a flag */
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {"local",    no_argument,       0, 'l'},
        {"server",   no_argument,       0, 's'},
        {"client",   no_argument,       0, 'c'},
        /* Options that pass in arguments */
        {"srv-ip",   required_argument, 0, 0},
        {"idx",      required_argument, 0, 0},

        /* End of entry */
        {0,          0,                 0, 0}
    };

    while (1) {

        int option_index = 0;

        c = getopt_long(argc, argv, "vhrls", long_options, &option_index);

        if (c == -1)
            break;

        switch(c) {
            case 0:
                switch (option_index) {
                    case 5:
                        strcpy((char *) server_ip, optarg);
                        printf("source ip %s[%s] set\n", server_ip, optarg);
                        break;
                    case 6:
                        if (optarg) {
                            client_idx = atoi(optarg);
                            printf("node index %d[%s] set.\n", client_idx, optarg);
                        } else {
                            printf("if this instance is inteded to be run as a client, please provide an index id.\n");
                            usage();
                            exit(1);
                        }
                    default:
                        break;
                }
                break;
            case 'h':
                usage();
                exit (1);
            case 'c':
                if (!mode_set) {
                    server_flag = 0;
                    client_flag = 1;
                    mode_set = 1;
                    printf("client mode set.\n");
                } else {
                    printf("server mode already set.\n");
                }
                break;
            case 's':
                if (!mode_set) {
                    server_flag = 1;
                    client_flag = 0;
                    mode_set = 1;
                    printf("sever mode set.\n");
                } else {
                    printf("client mode already set.\n");
                }
                break;
            case 'v':
                vflag = 1;
                printf("verbose mode.\n");
                break;
            case 'l':
                local_mode = 1;
                printf("local only test.\n");
                break;
            default:
                break;
        }
    }

    memset(enc_list, 0, 1024);
    for (idx = optind; idx < argc; ++idx) {
        sprintf((char *) enc_list, "%s%s", enc_list, argv[idx]);
        enc_len += strlen(argv[idx]);
    }

    if (vflag)
        printf("extra encryption engrediance used: %s.\n", enc_list);

    // open socket. if running in local test mode, use UNIX domain socket, use inet sock otherwise
    sock = socket (AF_INET, SOCK_STREAM, 0);
    if (vflag) {
        printf("socket id %d\n", sock);
    }

    idx = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &idx, sizeof(int));

    // preparing the socket, unix or inet
    //memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    if (vflag)
        printf("branch logic starts.\n");

    if (vflag)
        printf("vortex init.\n");
    vortex_init();

    if (server_flag) {
        // accept up to 10 connections
        pthread_t thread_id[10];


        // plot server acceptance address
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if ((bind(sock, (struct sockaddr *) &addr, sizeof(addr))) != 0) {
            printf("socket bind failed...\n");
            exit(0);
        } else {
            if (vflag)
                printf("Socket successfully binded...\n");
        }

        // allow up to 10 connection queues
        if ((listen(sock, 10)) != 0) {
            printf("listen failed...\n");
            exit(0);
        } else {
            pthread_attr_t tattr;

            pthread_attr_init(&tattr);
            pthread_attr_setschedpolicy(&tattr, SCHED_RR);

            while (1) {
                server_arg_t thread_arg;

                memset(&thread_arg, 0, sizeof(thread_arg));

                printf("Server listening, awaiting for client %d to connect.\n", client_idx);
                thread_arg.sock_fd = accept(sock, (struct sockaddr *) &(thread_arg.addr), &(thread_arg.addr_size));
                thread_arg.vflag = vflag;
                // calculate encryption key
                sprintf((char *) thread_arg.key_eng, "%s%d", enc_list, client_idx);
                printf("Client %d connected.\n", client_idx);
                if (vflag)
                    printf("using string [%s] for encryption key generation.\n", thread_arg.key_eng);
                thread_arg.enc_len = enc_len + 1;
                thread_arg.client_idx = client_idx;


                // generate new pipe, create new thread
                if (pthread_create(&thread_id[client_idx], &tattr, serverThread, &thread_arg) != 0)
                    printf("failed to create thread.\n");

                if (vflag)
                    printf("client %d connected at socket %d. communication thread started.\n",
                            client_idx, thread_arg.sock_fd);

                pthread_join(thread_id[client_idx], NULL);
                printf("pthread join successful.\n");

                printf("going for the next connection.\n");
                ++client_idx;
            }
            pthread_attr_destroy(&tattr);
        }
    } else if (client_flag) {
        int n;
        char buff[128];

        if (vflag)
            printf("using server address: %s\n", (local_mode) ? "127.0.0.1" : (char *) server_ip);

        addr.sin_addr.s_addr = inet_addr((local_mode) ? "127.0.0.1" : (char *) server_ip);
        if ((connect(sock, (struct sockaddr *) &addr, sizeof(addr))) == -1) {
            printf("connection to server error.\n");
            exit(1);
        } else {
            printf("Server connection established.\n");
            // calculate encryption key
            sprintf((char *) enc_list, "%s%d", enc_list, client_idx);
            enc_len += 1;
            if (vflag)
                printf("using string [%s] for encryption key generation.\n", enc_list);

            vortex_assign(sock, enc_len, (enc_len == 0) ? (unsigned char *) "" : (unsigned char *) enc_list);

            if (vflag) {
                unsigned char key[1024];
                int key_size = 0, key_idx = 0;

                key_size = (int) vortex_retrieve_key(sock, (unsigned char **) &key);

                printf("encryption key constructed from token: %s\n", enc_list);
                printf("encryption key size is %d\n", key_size);
                printf("key: 0x");
                for (; key_idx < key_size; ++key_idx) {
                    printf("%02x", key[key_idx]);
                }
                printf("\n");
            }


            // start sending data
            while (1) {
                bzero(buff, sizeof(buff));
                bzero(output, sizeof(output));
                printf("Enter message to send: ");
                n = 0;

                while ((buff[n++] = getchar()) != '\n');

                if ((output_len = vortex_crypto(sock, (unsigned char *) buff, n, output, ENCRYPT)) == -1) {
                    printf("please review vortex configuration, make sure the encryption path is assigned properly.\n");
                    break;
                }

                output[output_len] = '\0';

                if (vflag) {
                    printf("input \"%s\"(%d), encrypted %d bytes to\n\t",
                            buff, n,
                            output_len);
                    for (idx = 0; idx < output_len; ++idx) {
                        printf("%02x", output[idx]);
                    }
                    printf("\n");
                }

                //write(sock, buff ,sizeof(buff));
                write(sock, output, output_len);
                if ((strncmp(buff, "exit", 4)) == 0) {
                    printf("Client exit...\n");
                    break;
                }

                bzero(buff, sizeof(buff));
                bzero(output, sizeof(output));
                n = read(sock, buff, sizeof(buff));
                if (vflag)
                    printf("decrypting %d bytes date received\n", n);
                output_len = vortex_crypto(sock, (unsigned char *) buff, n, output, DECRYPT);

                if (vflag)
                    printf("decryption %d bytes to \"%s\"\n", output_len, (char *) output);
                printf("From server: %s\n", output);
            }

            close(sock);

            vortex_resign(sock);
        }
    }
}

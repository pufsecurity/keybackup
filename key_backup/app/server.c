/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/
/**
 * @file      server.c
 * @brief     server for project
 * @copyright 2023 PUFsecurity
 *
 */

#include "libcore.h"

server_state_t g_server_state = INIT;

// send message to server
void send_to_client(packet_st *packet) {
    SSL_write(packet->ssl, packet->send_buf, packet->send_buf_size);
}

// receive message from server
int recv_from_client(packet_st *packet) {
    packet->recv_buf_size = SSL_read(packet->ssl, packet->recv_buf, RECV_BUF_MAX);
    return packet->recv_buf_size;
}

static pufs_status_t ecdh_exchange_handle(packet_st *packet)
{
    int header_len;
    pufs_status_t check = PUFS_SUCCESS;

    header_len = sizeof(ecdh_packet_st) - sizeof(pufs_tuple_bytes_array_st) * 2;
    memcpy(packet->send_buf, packet->recv_buf, header_len);

    check = ecdh_keys(packet);
    if (check != PUFS_SUCCESS) {
        APP_ERR("ecdh_keys failed, check = %d", check);
    }
    packet->send_ecdh_packet->puk_ephemeral.len = packet->puk_server_e.len;
    packet->send_ecdh_packet->puk_static.len = packet->puk_server_s.len;
    packet->send_buf_size = header_len + sizeof(pufs_tuple_bytes_array_st) * 2;
    packet->puk_client_e.len = packet->recv_ecdh_packet->puk_ephemeral.len;
    packet->puk_client_s.len = packet->recv_ecdh_packet->puk_static.len;
    strncpy(packet->send_ecdh_packet->packet_name, "ECDH_SERVER", 12);

    check = generate_ecdh_kek(packet);
    if (check != PUFS_SUCCESS) {
        APP_ERR("generate_ecdh_kek failed, check = %d", check);
    }
    return check;
}

int server_event_handle(packet_st *packet)
{
    int ret = 0;
    pufs_status_t check = PUFS_SUCCESS;
    server_state_t event = (server_state_t)packet->recv_ecdh_packet->event;
    g_server_state = ERROR;
    switch (event) {
        case ECDH_EXCHANGE:
            check = ecdh_exchange_handle(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("ecdh_exchange_handle = %d", check);
            }
            else {
                g_server_state = ECDH_SHARED;
            }
            break;
        case BACKUP_KEY:
            check = server_import_wrap(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("server_import_wrap fail. check = %d", check);
                ret = 1;
                g_server_state = ERROR;
                break;
            }
            check = server_export_to_file(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("server_export_to_file fail. check = %d", check);
                ret = 1;
                g_server_state = ERROR;
                break;
            }
            result_packet_st *result_packet = (result_packet_st*)(packet->send_buf);
            result_packet->event = FINAL_RESULT;
            result_packet->result = SERVER_SUCCESS;
            strncpy(result_packet->packet_name, "RESULT_SERVER", 14);
            packet->send_buf_size = sizeof(result_packet_st);
            g_server_state = SERVER_HANDLER;
            break;
        case RESTORE_KEY:
            check = server_import_from_file(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("server_import_from_file fail. check = %d\n", check);
                ret = 1;
                g_server_state = ERROR;
                break;
            }
            check = server_wrap_packet(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("server_wrap_packet fail. check = %d\n", check);
                ret = 1;
                g_server_state = ERROR;
                break;
            }
            packet->send_buf_size = sizeof(wrap_packet_st);
            g_server_state = SERVER_HANDLER;
            break;
        case FINAL_RESULT:
            APP_DBG("(%d) event:[%d]\n", __LINE__, event);
            break;
        default:
            APP_ERR("(%d) event:[%d]\n", __LINE__, event);
            break;
    }
    return ret;
}

void server_packet_init(packet_st *server_packet)
{
    server_packet->type = SERVER;
    server_packet->send_ecdh_packet = (ecdh_packet_st *)(server_packet->send_buf);
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(server_packet->send_ecdh_packet->puk_ephemeral, &(server_packet->puk_server_e));
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(server_packet->send_ecdh_packet->puk_static, &(server_packet->puk_server_s));

    server_packet->recv_ecdh_packet = (ecdh_packet_st *)(server_packet->recv_buf);
    server_packet->recv_ecdh_packet->event = ECDH_EXCHANGE;
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(server_packet->recv_ecdh_packet->puk_ephemeral, &(server_packet->puk_client_e));
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(server_packet->recv_ecdh_packet->puk_static, &(server_packet->puk_client_s));
}

void server_state_handle(packet_st *packet)
{
    int ret = 0;
    g_server_state = CONNECTED;
    server_event_t event;
    result_packet_st *result_packet = (result_packet_st*)(packet->send_buf);
    pufs_status_t check = PUFS_SUCCESS;

    check = pufs_start(__func__);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_module_init failed, check = %d", check);
        goto EXIT;
    }
    enroll();
    while (1) {
        switch (g_server_state) {
            case CONNECTED:
                ret = recv_from_client(packet);
                if (ret < 0) {
                    APP_ERR("recv_from_client fail. \n");
                    g_server_state = ERROR;
                }
                event = (server_event_t)packet->recv_ecdh_packet->event;

                if (event == ECDH_EXCHANGE) {
                    ret = server_event_handle(packet);
                    if (packet->send_buf_size) {
                        send_to_client(packet);
                    }
                }
                else {
                    APP_ERR("(%d) Incorrect event:[%d] state:[%d]\n", __LINE__, event, g_server_state);
                    g_server_state = ERROR;
                }
                break;
            case ECDH_SHARED:
                ret = recv_from_client(packet);
                if (ret < 0) {
                    APP_ERR("recv_from_client fail. \n");
                    g_server_state = ERROR;
                }
                event = (server_event_t)packet->recv_ecdh_packet->event;
                if ((event == BACKUP_KEY) || (event == RESTORE_KEY)) {
                    ret = server_event_handle(packet);
                    if (ret) {
                        g_server_state = ERROR;
                    }
                }
                else {
                    APP_ERR("(%d) Incorrect event:[%d] state:[%d]\n", __LINE__, event, g_server_state);
                    g_server_state = ERROR;
                }
                break;
            case SERVER_HANDLER:
                event = result_packet->event;
                send_to_client(packet);
                g_server_state = FINISH;
                break;
            default:
                APP_ERR("unknown state:[%d]\n", g_server_state);
                g_server_state = ERROR;
                break;
        }

        if ((g_server_state == ERROR) || (g_server_state == FINISH)) {
            break;
        }
        usleep(1000);
    }
    check = pufs_end(__func__);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_end failed, check = %d", check);
        goto EXIT;
    }
EXIT:
    return;
}

#define ARP_FILE "/proc/net/arp"
int query_arp(char *ip, char *mac) {
    FILE *fp;
    char line[256], ip_address[16], mac_address[18];
    int i, j, ret = 0;

    fp = fopen(ARP_FILE, "r");
    if (fp == NULL) {
        perror("ARP file open failed");
        ret = 1;
        goto EXIT;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%s %*s %*s %s", ip_address, mac_address);
        if (strcmp(ip_address, ip) == 0) {
            for (i = 0, j = 0; mac_address[i]; i++) {
                if (mac_address[i] != ':') {
                    mac[j++] = mac_address[i];
                }
            }
            mac[j] = '\0';
            break;
        }
    }

    fclose(fp);
EXIT:
    return ret;
}


void usage(char *argv0)
{
    printf("Usage: %s [-p SERVER_PORT] [-d key_file_path] [-m]\n", argv0);
    printf("           -m: mutual TLS\n\n");
}


void print_cert_info(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        X509_NAME* subject_name = X509_get_subject_name(cert);
        BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509_NAME_print_ex(bio, subject_name, 0, XN_FLAG_ONELINE);
        BIO_free(bio);
        X509_free(cert);
        printf("\n");
    } else {
        printf("No client certificate.\n");
    }
}


int create_ssl_ctx(SSL_CTX **ctx, int mutual)
{
    // create SSL ctx
    *ctx = SSL_CTX_new(TLS_server_method());
    //ctx = SSL_CTX_new(SSLv23_server_method());  // old openssl
    if (*ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // set server crt
    if (SSL_CTX_use_certificate_file(*ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    // set server privte key
    if (SSL_CTX_use_PrivateKey_file(*ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 3;
    }

    // set CA file
    if (!SSL_CTX_load_verify_locations(*ctx, "ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Client Certificate Request
    if (mutual) {
        printf("Enable mutual TLS.\n");
        SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    return 0;
}

void handle_syscall_error(void) {
    int error_code = errno;

    switch (error_code) {
        case EINTR:
            printf("A system call was interrupted by a signal\n");
            break;
        case EAGAIN:
            printf("Resource temporarily unavailable\n");
            break;
        case ECONNRESET:
            printf("Connection reset by peer\n");
            break;
        default:
            printf("System call error occurred: %d\n", error_code);
            break;
    }
}

void handle_ssl_error(SSL* ssl, int ret) {
    int err = SSL_get_error(ssl, ret);

    switch (err) {
        case SSL_ERROR_NONE:
            printf("No error occurred\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("The TLS/SSL connection has been closed\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("The operation did not complete; wait for a readable socket and try again\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("The operation did not complete; wait for a writable socket and try again\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("The operation did not complete; wait for a connectable socket and try again\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("The operation did not complete; wait for an acceptable socket and try again\n");
            break;
        case SSL_ERROR_SYSCALL:
            printf("A system call error occurred\n");
            handle_syscall_error();
            break;
        case SSL_ERROR_SSL:
            printf("A failure in the SSL library occurred\n");
            break;
        default:
            printf("An unknown error occurred\n");
            break;
    }
}

int main(int argc, char *argv[])
{
    int opt, sockfd, new_fd, path_len, ret = 0, mutual = 0;
    char *port = SERVER_PORT;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    char ipstr[INET6_ADDRSTRLEN];
    int rv;
    SSL_CTX *ctx;
    packet_st server_packet;
    int shutdownResult;
    int shutdownCount = 0;

    memset(&server_packet, 0, sizeof(packet_st));

    while ((opt = getopt(argc, argv, "p:d:m")) != -1) {
        switch (opt) {
            case 'p':
                port = optarg;
                break;
            case 'd':
                if (!optarg) {
                    APP_ERR("path is NULL!!\n");
                    goto EXIT;
                }
                path_len = strlen(optarg);
                if (path_len > KEY_FILE_PATH_MAX - 1) {
                    APP_ERR("path_len:[%d] too large!!\n", path_len);
                    goto EXIT;
                }
                if (access(optarg, F_OK) != 0) {
                    APP_ERR("%s did not exist!!\n", optarg);
                    goto EXIT;
                }
                if (access(optarg, W_OK) != 0) {
                    APP_ERR("%s can NOT access!!\n", optarg);
                    goto EXIT;
                }

                strncpy(server_packet.key_file_path, optarg, path_len);
                if (server_packet.key_file_path[path_len - 1] != '/') {
                    server_packet.key_file_path[path_len] = '/';
                }
                break;
            case 'm':
                mutual = 1;
                break;
            default:
                usage(argv[0]);
                goto EXIT;
        }
    }
    server_packet_init(&server_packet);

    // initial OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();

    printf("argc:[%d] argv[0]:[%s] port:[%s]\n", argc, argv[0], port);

    // create TCP socket
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        ret = 4;
        goto EXIT;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("bind");
            continue;
        }
        break;
    }
    if (p == NULL) {
        fprintf(stderr, "Failed to bind socket\n");
        ret = 5;
        goto EXIT;
    }
    freeaddrinfo(servinfo);
    if (listen(sockfd, 10) == -1) {
        perror("listen");
        ret = 6;
        goto EXIT;
    }

    ret = create_ssl_ctx(&ctx, mutual);
    if (ret != 0) goto EXIT;

    printf("Server is listening on port %s...\n", port);

    while (1) {
        sin_size = sizeof(their_addr);
        shutdownCount = 0;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                &(((struct sockaddr_in *)&their_addr)->sin_addr),
                ipstr, sizeof ipstr);
        ret = query_arp(ipstr, server_packet.macaddress);
        if (ret) {
            APP_ERR("Unknown client MAC address!!. query_arp ret:[%d]\n", ret);
            continue;
        }
        printf("Server %s got connection from %s %s\n", SERVER_ADDR, ipstr, server_packet.macaddress);

        // SSL connection
        server_packet.ssl = SSL_new(ctx);
        SSL_set_fd(server_packet.ssl, new_fd);
        if (SSL_accept(server_packet.ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_fd);
            continue;
        }
        print_cert_info(server_packet.ssl);

        server_state_handle(&server_packet);

        // close SSL
        do {
            shutdownResult = SSL_shutdown(server_packet.ssl);
            shutdownCount++;
            if (shutdownCount > 10) {
                APP_ERR("(%d) shutdownCount over 10 !!!\n", __LINE__);
                break;
            }
            sleep(1);
        } while (shutdownResult == 0);

        if (new_fd != -1) {
            close(new_fd);
            new_fd = -1;
        }

        if (shutdownResult == 1) {
            SSL_clear(server_packet.ssl);
            SSL_free_buffers(server_packet.ssl);
            SSL_free(server_packet.ssl);
        } else if (shutdownResult == -1) {
            unsigned long err = ERR_get_error();
            handle_ssl_error(server_packet.ssl, shutdownResult);
            APP_ERR("(%d) ssl close fail, ERR_get_error return:[%ld]!!!\n", __LINE__, err);
        }
        STATISTICS_SHOW();
    }

    if (ctx) {
        APP_DBG("(%d) SSL_CTX_free(ctx);!!!\n", __LINE__);
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

EXIT:
    return ret;
}


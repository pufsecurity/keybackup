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
 * @file      client.c
 * @brief     client for project
 * @copyright 2023 PUFsecurity
 *
 */

#include "libcore.h"

server_state_t g_client_state = INIT;

void SSL_CTX_keylog_cb_func_cb(const SSL *ssl __attribute__((unused)), const char *line) {
    FILE  * fp;
    //printf("ssl:[%p]\n", (void *)ssl);
    fp = fopen("key_log.log", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}

void print_cert_info(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        /*
        printf("Server Certificate:\n");
        char* cert_info = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("%s\n", cert_info);
        free(cert_info);
        */
        X509_NAME* subject_name = X509_get_subject_name(cert);
        BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509_NAME_print_ex(bio, subject_name, 0, XN_FLAG_ONELINE);
        BIO_free(bio);
        X509_free(cert);
        printf("\n");
        X509_free(cert);
    } else {
        printf("No server certificate.\n");
    }
}

int create_ssl_connect(SSL **ssl, SSL_CTX **ctx, int *sockfd, char *ipaddr, char *port) {
    struct addrinfo hints, *servinfo, *p;
    char ipstr[INET6_ADDRSTRLEN];
    int rv, ret = 0;
    void *addr;

    // initial OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();

    // server address
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo(ipaddr, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        ret = 1;
        goto EXIT;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        printf("start client~~~\n");
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        // ip to string
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("Connecting to %s\n", ipstr);

        // create TCP socket
        if ((*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }
        if (connect(*sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(*sockfd);
            perror("connect");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect to server\n");
        ret = 2;
        goto EXIT;
    }
    freeaddrinfo(servinfo);

    // SSL connection
    *ctx = SSL_CTX_new(TLS_client_method());  // TLSv1.3
    //ctx = SSL_CTX_new(SSLv23_client_method());  //old SSL

    // Key log
    SSL_CTX_set_keylog_callback(*ctx, SSL_CTX_keylog_cb_func_cb);

    // set client crt
    if (SSL_CTX_use_certificate_file(*ctx, "client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    // set client privte key
    if (SSL_CTX_use_PrivateKey_file(*ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 3;
    }

    // set CA file
    if (!SSL_CTX_load_verify_locations(*ctx, "ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify server
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);

    *ssl = SSL_new(*ctx);
    SSL_set_fd(*ssl, *sockfd);
    if (SSL_connect(*ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        ret = 3;
        goto EXIT;
    }
    print_cert_info(*ssl);
EXIT:
    return ret;
}

// send message to server
int send_to_server(packet_st *packet) {
    return SSL_write(packet->ssl, packet->send_buf, packet->send_buf_size);
}

// receive message from server
int recv_from_server(packet_st *packet) {
    packet->recv_buf_size = SSL_read(packet->ssl, packet->recv_buf, RECV_BUF_MAX);
    return packet->recv_buf_size;
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

void close_ssl(SSL **ssl)
{
    // close SSL
    int shutdownResult;
    int shutdownCount = 0;

    if (*ssl) {
        int socket_fd = SSL_get_fd(*ssl);
        SSL_shutdown(*ssl);

        do {
            shutdownResult = SSL_shutdown(*ssl);
            shutdownCount++;
            if (shutdownCount > 10) {
                APP_ERR("(%d) shutdownCount over 10 !!!\n", __LINE__);
                break;
            }
            sleep(1);
        } while (shutdownResult == 0);

        if (shutdownResult == 1) {
            SSL_clear(*ssl);
            SSL_free_buffers(*ssl);
            SSL_free(*ssl);
        } else if (shutdownResult == -1) {
            handle_ssl_error(*ssl, shutdownResult);
            unsigned long err = ERR_get_error();
            APP_ERR("(%d) ssl close fail, ERR_get_error return:[%ld]!!!\n", __LINE__, err);
        }

        if (socket_fd > 0)
            close(socket_fd);
        *ssl = NULL;
    }
}

void close_ctx(SSL_CTX **ctx)
{
    if (*ctx) {
        SSL_CTX_free(*ctx);
        *ctx = NULL;
    }
}


void free_ssl_connect(SSL **ssl, SSL_CTX **ctx)
{
    close_ssl(ssl);
    close_ctx(ctx);
}
static pufs_status_t ecdh_exchange_handle(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;

    packet->puk_server_e.len = packet->recv_ecdh_packet->puk_ephemeral.len;
    packet->puk_server_s.len = packet->recv_ecdh_packet->puk_static.len;

    check = generate_ecdh_kek(packet);
    if (check != PUFS_SUCCESS) {
        APP_ERR("generate_ecdh_kek failed, check = %d", check);
    }
    return check;
}

int client_event_handle(packet_st *packet)
{
    int ret = 0;
    pufs_status_t check = PUFS_SUCCESS;
    server_event_t event = *(server_event_t*)packet->recv_buf;
    result_packet_st *result_packet = (result_packet_st *)packet->recv_buf;
    g_client_state = ERROR;
    switch (event) {
        case ECDH_EXCHANGE:
            check = ecdh_exchange_handle(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("ecdh_exchange_handle fail\n");
                break;
            }

            // ecdh exchange success.
            if (packet->cmd == BACKUP) {
                check = client_wrap_packet(packet);
                if (check != PUFS_SUCCESS) {
                    APP_ERR("client_wrap_packet fail\n");
                    g_client_state = ERROR;
                    break;
                }
            }
            else if (packet->cmd == RESTORE) {
                check = client_require_wrap_packet(packet);
                if (check != PUFS_SUCCESS) {
                    APP_ERR("client_require_wrap_packet fail\n");
                    g_client_state = ERROR;
                    break;
                }
            }
            else {
                APP_ERR("Unknown packet command: %d\n", packet->cmd);
            }

            g_client_state = CLIENT_HANDLER;
            break;
        case BACKUP_KEY:
            APP_DBG("(%d) event:[%d]\n", __LINE__, event);
            break;
        case RESTORE_KEY:
            check = client_import_wrap(packet);
            if (check != PUFS_SUCCESS) {
                APP_ERR("client_import_wrap fail. check = %d", check);
                ret = 1;
                g_client_state = ERROR;
                break;
            }
            break;
        case FINAL_RESULT:
            if (result_packet->result == SERVER_SUCCESS) {
                printf("key backup OK\n");
                g_client_state = FINISH;
            }
            else {
                printf("key backup FAIL\n");
                g_client_state = ERROR;
            }
            break;
        default:
            APP_ERR("(%d) event:[%d]\n", __LINE__, event);
            break;
    }
    return ret;
}


void client_packet_init(packet_st *client_packet)
{
    client_packet->type = CLIENT;
    client_packet->send_ecdh_packet = (ecdh_packet_st *)(client_packet->send_buf);
    client_packet->send_ecdh_packet->event = ECDH_EXCHANGE;
    client_packet->send_ecdh_packet->key_num = 2;
    client_packet->send_ecdh_packet->ecdh_key_ephemeral.key_type = ECDH_EPHEMERAL_KEY;
    client_packet->send_ecdh_packet->ecdh_key_ephemeral.key_len = sizeof(pufs_tuple_bytes_array_st);
    client_packet->send_ecdh_packet->ecdh_key_static.key_type = ECDH_STATIC_KEY;
    client_packet->send_ecdh_packet->ecdh_key_static.key_len = sizeof(pufs_tuple_bytes_array_st);
    client_packet->send_ecdh_packet->puk_ephemeral.len = EC_POINT_MAXLEN;
    client_packet->send_ecdh_packet->puk_static.len = EC_POINT_MAXLEN;

    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(client_packet->send_ecdh_packet->puk_ephemeral, &(client_packet->puk_client_e));
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(client_packet->send_ecdh_packet->puk_static, &(client_packet->puk_client_s));


    client_packet->recv_ecdh_packet = (ecdh_packet_st *)(client_packet->recv_buf);
    client_packet->recv_ecdh_packet->event = ECDH_EXCHANGE;
    client_packet->recv_ecdh_packet->key_num = 2;
    client_packet->recv_ecdh_packet->ecdh_key_ephemeral.key_type = ECDH_EPHEMERAL_KEY;
    client_packet->recv_ecdh_packet->ecdh_key_ephemeral.key_len = sizeof(pufs_tuple_bytes_array_st);
    client_packet->recv_ecdh_packet->ecdh_key_static.key_type = ECDH_STATIC_KEY;
    client_packet->recv_ecdh_packet->ecdh_key_static.key_len = sizeof(pufs_tuple_bytes_array_st);
    client_packet->recv_ecdh_packet->puk_ephemeral.len = EC_POINT_MAXLEN;
    client_packet->recv_ecdh_packet->puk_static.len = EC_POINT_MAXLEN;

    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(client_packet->recv_ecdh_packet->puk_ephemeral, &(client_packet->puk_server_e));
    PUFS_TUPLE_BYTES_ARRAY_TO_POINT(client_packet->recv_ecdh_packet->puk_static, &(client_packet->puk_server_s));
}

int edch_packet(packet_st *packet) {
    pufs_status_t check = PUFS_SUCCESS;
    check = ecdh_keys(packet);
    if (check != PUFS_SUCCESS) {
        APP_ERR("ecdh_keys failed, check = %d", check);
        goto RET;
    }
    strncpy(packet->send_ecdh_packet->packet_name, "ECDH_CLIENT", 12);
    packet->send_ecdh_packet->puk_ephemeral.len = packet->puk_client_e.len;
    packet->send_ecdh_packet->puk_static.len = packet->puk_client_s.len;

    packet->send_buf_size = sizeof(ecdh_packet_st);

RET:
    return check;
}

void client_state_handle(packet_st *packet)
{
    int ret = 0;
    g_client_state = CONNECTED;
    server_event_t event;
    pufs_status_t check = PUFS_SUCCESS;

    check = pufs_start(__func__);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_module_init failed, check = %d", check);
        goto EXIT;
    }

    enroll();
    while(1) {
        switch (g_client_state) {
            case CONNECTED:
                ret = edch_packet(packet);
                if (ret != PUFS_SUCCESS) {
                    APP_ERR("edch_packet, ret = %d", ret);
                    g_client_state = ERROR;
                }
                if (g_client_state != ERROR) {
                    ret = send_to_server(packet);
                    if (ret < 0) {
                        APP_ERR("send_to_server fail. \n");
                        g_client_state = ERROR;
                    }
                    else {
                        g_client_state = ECDH_SHARED;
                    }
                }
                break;
            case ECDH_SHARED:
                ret = recv_from_server(packet);
                if (ret < 0) {
                    APP_ERR("recv_from_server fail. \n");
                    break;
                }
                event = (server_event_t)packet->recv_ecdh_packet->event;
                if (event == ECDH_EXCHANGE) {
                    client_event_handle(packet);
                    ret = send_to_server(packet);
                    if (ret < 0) {
                        APP_ERR("send_to_server fail. \n");
                        g_client_state = ERROR;
                    }
                    else {
                        g_client_state = CLIENT_HANDLER;
                    }
                }
                else {
                    APP_ERR("(%d) Incorrect event:[%d] state:[%d]\n", __LINE__, event, g_client_state);
                    g_client_state = ERROR;
                }

                break;
            case CLIENT_HANDLER:
                ret = recv_from_server(packet);
                if (ret < 0) {
                    APP_ERR("recv_from_server fail. \n");
                    break;
                }
                event = (server_event_t)packet->recv_ecdh_packet->event;
                if ((event == FINAL_RESULT) || (event == RESTORE_KEY)) {
                    client_event_handle(packet);
                    g_client_state = FINISH;
                }
                else {
                    APP_ERR("ERROR event:[%d]\n", event);
                    g_client_state = ERROR;
                }
                break;
            default:
                APP_ERR("unknown state:[%d]\n", g_client_state);
                g_client_state = ERROR;
                break;
        }
        if ((g_client_state == ERROR) || (g_client_state == FINISH)) {
            break;
        }
    }
    check = pufs_end(__func__);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_end failed, check = %d", check);
        goto EXIT;
    }

EXIT:
    return;
}

void usage(char *argv0)
{
    printf("Usage: %s [-a SERVER_IP] [-p SERVER_PORT] [-c PASSWD] [-m MAC_ADDR] [-r]\n", argv0);
    printf("    -r  restore key from server\n");
    printf("    -m  MAC address\n\n");
}


int main(int argc, char *argv[])
{
    int opt, sockfd = -1;
    SSL_CTX *ctx = NULL;
    int ret = 0;
    packet_st client_packet;
    char *ipaddr = NULL, *port = NULL, *passwd = NULL;//, *restore;
    size_t i;

    memset(&client_packet, 0, sizeof(packet_st));

    client_packet.cmd = BACKUP;
    while ((opt = getopt(argc, argv, "a:p:c:rm:")) != -1) {
        switch (opt) {
            case 'a':
                ipaddr = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 'c':
                passwd = optarg;
                break;
            case 'm':
                //macaddr = optarg;
                //sprintf(client_packet.macaddress, "%s", optarg);
                for(i = 0; i < strlen(optarg); i++) {
                    if(optarg[i] >= 'A' && optarg[i] <= 'Z') {
                        client_packet.macaddress[i] = optarg[i] + 32;
                    }
                    else {
                        client_packet.macaddress[i] = optarg[i];
                    }
                }
                break;
            case 'r':
                client_packet.cmd = RESTORE;
                break;
            default:
                usage(argv[0]);
                goto EXIT;
        }
    }

    if ((!ipaddr) || (!port) || (!passwd)) {
        usage(argv[0]);
        goto EXIT;
    }

    if ((client_packet.cmd == RESTORE) && (strlen(client_packet.macaddress) == 0)) {
        printf("missing MAC_ADDR for restore!\n");
        goto EXIT;
    }
    client_packet_init(&client_packet);
    if (strlen(passwd) > PASSWD_MAX) {
        printf("Password length must be less than %d!!\n", PASSWD_MAX);
        goto EXIT;
    }
    memcpy(client_packet.passwd, passwd, strlen(passwd));

    ret = create_ssl_connect(&client_packet.ssl, &ctx, &sockfd, ipaddr, port);
    if (ret != 0) {
        APP_ERR("create_ssl_connect fail, ret = %d\n", ret);
        goto EXIT;
    }

    client_state_handle(&client_packet);
    free_ssl_connect(&client_packet.ssl, &ctx);
EXIT:
    STATISTICS_SHOW();
    return ret;
}


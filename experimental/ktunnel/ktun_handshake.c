// SPDX-License-Identifier: MIT
/*
 * Hardened Userspace TCP_REPAIR Handshake Daemon for `k_tcpmux.ko`.
 *
 * Fixes all memory-safety & error-handling issues:
 *   - Strict argc validation (`server <srv_port> <base_cport>` vs `client <rem_ip> <srv_port> <base_cport>`).
 *   - Bounds-checked flow index (`0 <= idx < MUX_FLOW_COUNT`) preventing out-of-bounds array writes.
 *   - Full return-value verification on socket(), setsockopt(), bind(), listen(), accept(),
 *     inet_pton(), get_seq_nums(), and sync_to_kernel().
 *   - Graceful SIGTERM/SIGINT teardown closing all subflow FDs cleanly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MUX_FLOW_COUNT 8

#ifndef TCP_REPAIR
#define TCP_REPAIR          19
#define TCP_REPAIR_QUEUE    20
#define TCP_QUEUE_SEQ       21
#define TCP_RECV_QUEUE      1
#define TCP_SEND_QUEUE      2
#endif

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static int sync_to_kernel(int idx, uint32_t snd_nxt, uint32_t rcv_nxt, uint16_t sport, uint16_t dport)
{
    FILE *fp = fopen("/proc/net/ktun_sync", "w");
    if (!fp) {
        perror("fopen(/proc/net/ktun_sync)");
        return -1;
    }
    if (fprintf(fp, "%d %u %u %u %u\n", idx, snd_nxt, rcv_nxt, sport, dport) < 0) {
        perror("fprintf(/proc/net/ktun_sync)");
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        perror("fclose(/proc/net/ktun_sync)");
        return -1;
    }
    return 0;
}

static int get_seq_nums(int fd, uint32_t *snd_nxt, uint32_t *rcv_nxt)
{
    int val = 1, q;
    socklen_t len = sizeof(uint32_t);

    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &val, sizeof(val)) < 0) {
        perror("setsockopt(TCP_REPAIR=1)");
        return -1;
    }
    q = TCP_SEND_QUEUE;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q)) < 0 ||
        getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, snd_nxt, &len) < 0) {
        perror("getsockopt(TCP_SEND_QUEUE)");
        val = 0;
        (void)setsockopt(fd, SOL_TCP, TCP_REPAIR, &val, sizeof(val));
        return -1;
    }
    q = TCP_RECV_QUEUE;
    len = sizeof(uint32_t);
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q)) < 0 ||
        getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, rcv_nxt, &len) < 0) {
        perror("getsockopt(TCP_RECV_QUEUE)");
        val = 0;
        (void)setsockopt(fd, SOL_TCP, TCP_REPAIR, &val, sizeof(val));
        return -1;
    }
    val = 0;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &val, sizeof(val)) < 0) {
        perror("setsockopt(TCP_REPAIR=0)");
        return -1;
    }
    return 0;
}

static int parse_port(const char *s, uint16_t *out)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s || *s == '\0' || (end && *end != '\0') || v <= 0 || v > 65535)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    int fds[MUX_FLOW_COUNT];
    int lfd = -1;

    for (int i = 0; i < MUX_FLOW_COUNT; i++)
        fds[i] = -1;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n  %s server <srv_port> <base_cport>\n  %s client <remote_ip> <srv_port> <base_cport>\n",
                argv[0], argv[0]);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int is_srv = (strcmp(argv[1], "server") == 0);
    int is_cli = (strcmp(argv[1], "client") == 0);
    if (!is_srv && !is_cli) {
        fprintf(stderr, "Invalid mode '%s' (expected 'server' or 'client')\n", argv[1]);
        return 1;
    }

    if (is_srv) {
        uint16_t srv_port = 0, base_cport = 0;
        if (argc < 4 || parse_port(argv[2], &srv_port) < 0 || parse_port(argv[3], &base_cport) < 0) {
            fprintf(stderr, "Usage: %s server <srv_port> <base_cport>\n", argv[0]);
            return 1;
        }
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) {
            perror("socket");
            return 1;
        }
        int opt = 1;
        if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("setsockopt(SO_REUSEADDR)");
            close(lfd);
            return 1;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(srv_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(lfd);
            return 1;
        }
        if (listen(lfd, 16) < 0) {
            perror("listen");
            close(lfd);
            return 1;
        }

        for (int i = 0; i < MUX_FLOW_COUNT && g_running; i++) {
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(lfd, (struct sockaddr *)&cli, &clen);
            if (cfd < 0) {
                perror("accept");
                goto cleanup;
            }
            uint16_t cport = ntohs(cli.sin_port);
            int idx = i;
            if (cport >= base_cport && (int)(cport - base_cport) < MUX_FLOW_COUNT) {
                int cand = (int)(cport - base_cport);
                if (fds[cand] < 0)
                    idx = cand;
            }
            uint32_t snd = 0, rcv = 0;
            if (get_seq_nums(cfd, &snd, &rcv) < 0 ||
                sync_to_kernel(idx, snd, rcv, srv_port, cport) < 0) {
                close(cfd);
                goto cleanup;
            }
            fds[idx] = cfd;
        }
    } else {
        uint16_t srv_port = 0, base_cport = 0;
        if (argc < 5 || parse_port(argv[3], &srv_port) < 0 || parse_port(argv[4], &base_cport) < 0) {
            fprintf(stderr, "Usage: %s client <remote_ip> <srv_port> <base_cport>\n", argv[0]);
            return 1;
        }
        if ((uint32_t)base_cport + MUX_FLOW_COUNT > 65535U) {
            fprintf(stderr, "base_cport %u too high for %d flows\n", base_cport, MUX_FLOW_COUNT);
            return 1;
        }
        const char *rem_ip = argv[2];
        struct in_addr dst_in;
        if (inet_pton(AF_INET, rem_ip, &dst_in) != 1) {
            fprintf(stderr, "Invalid remote IPv4 address '%s'\n", rem_ip);
            return 1;
        }

        for (int i = 0; i < MUX_FLOW_COUNT && g_running; i++) {
            int sfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sfd < 0) {
                perror("socket");
                goto cleanup;
            }
            int opt = 1;
            if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                perror("setsockopt(SO_REUSEADDR)");
                close(sfd);
                goto cleanup;
            }
            struct sockaddr_in laddr;
            memset(&laddr, 0, sizeof(laddr));
            laddr.sin_family = AF_INET;
            laddr.sin_port = htons((uint16_t)(base_cport + i));
            laddr.sin_addr.s_addr = INADDR_ANY;

            if (bind(sfd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
                perror("bind");
                close(sfd);
                goto cleanup;
            }

            struct sockaddr_in raddr;
            memset(&raddr, 0, sizeof(raddr));
            raddr.sin_family = AF_INET;
            raddr.sin_port = htons(srv_port);
            raddr.sin_addr = dst_in;

            while (g_running && connect(sfd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
                usleep(200000);
            }
            if (!g_running) {
                close(sfd);
                goto cleanup;
            }
            uint32_t snd = 0, rcv = 0;
            if (get_seq_nums(sfd, &snd, &rcv) < 0 ||
                sync_to_kernel(i, snd, rcv, (uint16_t)(base_cport + i), srv_port) < 0) {
                close(sfd);
                goto cleanup;
            }
            fds[i] = sfd;
        }
    }

    while (g_running) {
        pause();
    }

cleanup:
    if (lfd >= 0)
        close(lfd);
    for (int i = 0; i < MUX_FLOW_COUNT; i++) {
        if (fds[i] >= 0)
            close(fds[i]);
    }
    return 0;
}

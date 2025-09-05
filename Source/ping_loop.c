#include "ft_ping.h"

bool g_stop_ping_loop = false;

void IntHandler(int) {
    g_stop_ping_loop = true;
}

void PingPong(Context *ctx) {
    char readback_buffer[128];

    struct timespec total_start_time = {0};
    clock_gettime(CLOCK_MONOTONIC, &total_start_time);

    printf(
        "PING %s (%s): %d data bytes",
        ctx->dest_hostname_arg, ctx->dest_addr_str,
        (int)(sizeof(PingPacket) - sizeof(struct icmphdr))
    );
    if (ctx->verbose) {
        printf(", id 0x%04x = %u", htons(ctx->identifier), htons(ctx->identifier));
    }
    printf("\n");

    while (!g_stop_ping_loop) {
        struct timespec start_time = {0};
        clock_gettime(CLOCK_MONOTONIC, &start_time);

        SendICMPEchoPacket(ctx);
        if (g_stop_ping_loop) {
            break;
        }

        int received = ReceiveICMPPacket(ctx, readback_buffer, sizeof(readback_buffer));
        if (g_stop_ping_loop) {
            break;
        }

        if (received > 0) {
            struct timespec end_time = {0};
            clock_gettime(CLOCK_MONOTONIC, &end_time);

            double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0
                + (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

            PrintICMPPacket(ctx, readback_buffer, received, elapsed_ms);

            struct icmphdr *hdr = (struct icmphdr *)(readback_buffer + sizeof(struct iphdr));
        }

        usleep((int)(ctx->ping_interval_in_seconds * 1000000));
    }

    struct timespec total_end_time = {0};
    clock_gettime(CLOCK_MONOTONIC, &total_end_time);

    double total_elapsed_ms = (total_end_time.tv_sec - total_start_time.tv_sec) * 1000.0
        + (total_end_time.tv_nsec - total_start_time.tv_nsec) / 1000000.0;

    printf("\n--- %s ping statistics ---\n", ctx->dest_hostname_arg);
    if (ctx->error_num == 0) {
        printf(
            "%d packets transmitted, %d received, %.2f%% packet loss, time %.2f ms\n",
            ctx->echo_sent, ctx->reply_received,
            100 * (ctx->echo_sent - ctx->reply_received) / (float)(ctx->echo_sent),
            total_elapsed_ms
        );
    } else {
        printf(
            "%d packets transmitted, %d received, +%d errors, %.2f%% packet loss, time %d ms\n",
            ctx->echo_sent, ctx->reply_received,
            ctx->error_num,
            100 * (ctx->echo_sent - ctx->reply_received) / (float)(ctx->echo_sent),
            (int)total_elapsed_ms
        );
    }
}

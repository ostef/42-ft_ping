#include "ft_ping.h"
#include <math.h>

bool g_stop_ping_loop = false;

void IntHandler(int) {
    g_stop_ping_loop = true;
}

void PingPong(Context *ctx) {
    char readback_buffer[128];

    double min_time = INFINITY;
    double max_time = 0;
    double avg_time = 0;
    double stddev_time = 0;

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

        int prev_received_replies = ctx->reply_received;
        int received = ReceiveICMPPacket(ctx, readback_buffer, sizeof(readback_buffer));
        if (g_stop_ping_loop) {
            break;
        }

        if (received > 0) {
            struct timespec end_time = {0};
            clock_gettime(CLOCK_MONOTONIC, &end_time);

            double elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0
                + (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

            // Count timings
            if (ctx->reply_received > prev_received_replies) {
                if (elapsed_ms < min_time)
                    min_time = elapsed_ms;
                if (elapsed_ms > max_time)
                    max_time = elapsed_ms;

                avg_time += elapsed_ms;
                stddev_time += elapsed_ms * elapsed_ms;
            }

            PrintICMPPacket(ctx, readback_buffer, received, elapsed_ms);

            struct icmphdr *hdr = (struct icmphdr *)(readback_buffer + sizeof(struct iphdr));
        }

        usleep((int)(ctx->ping_interval_in_seconds * 1000000));
    }

    printf("\n--- %s ping statistics ---\n", ctx->dest_hostname_arg);
    printf(
        "%d packets transmitted, %d packets received, %.0f%% packet loss\n",
        ctx->echo_sent, ctx->reply_received,
        100 * (ctx->echo_sent - ctx->reply_received) / (float)(ctx->echo_sent)
    );
    if (ctx->reply_received > 0) {
        avg_time /= ctx->reply_received;
        stddev_time = sqrt((stddev_time / ctx->reply_received) - (avg_time * avg_time));
        printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", min_time, avg_time, max_time, stddev_time);
    }
}

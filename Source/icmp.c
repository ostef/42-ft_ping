#include "ft_ping.h"

// https://en.wikipedia.org/wiki/Internet_checksum
static unsigned short CalculateIPv4Checksum(void *ptr, int size) {
    unsigned short *buf = ptr;
    unsigned int sum = 0;

    int i = 0;
    for (; size > 1; size -= 2) {
        sum += buf[i];
        i += 1;
    }

    if (size == 1) {
        sum += buf[i];
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

int SendICMPEchoPacket(Context *ctx) {
    ctx->echo_sent += 1;

    PingPacket packet = {0};
    packet.header.type = ICMP_ECHO;
    packet.header.un.echo.id = getpid();
    packet.header.un.echo.sequence = ctx->echo_sent;

    for (int i = 0; i < sizeof(packet.msg) - 1; i += 1) {
        packet.msg[i] = '0' + i;
    }

    packet.msg[sizeof(packet.msg) - 1] = 0;

    packet.header.checksum = CalculateIPv4Checksum(&packet, sizeof(packet));

    int sent = 0;
    while (!g_stop_ping_loop) {
        sent = sendto(
            ctx->socket_fd,
            &packet, sizeof(packet),
            MSG_DONTWAIT,
            (struct sockaddr *)&ctx->dest_addr, sizeof(ctx->dest_addr)
        );

        if (sent < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                continue;
            else
                FatalErrorErrno("sendto", errno);
        }

        if (sent == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        }

        break;
    }

    return sent;
}

int ReceiveICMPPacket(Context *ctx, void *buff, int size) {
    int received = 0;
    while (!g_stop_ping_loop) {
        socklen_t addrlen = sizeof(ctx->dest_addr);
        received = recvfrom(
            ctx->socket_fd,
            buff, size,
            MSG_DONTWAIT,
            (struct sockaddr *)&ctx->dest_addr, &addrlen
        );

        if (received < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                FatalErrorErrno("recvfrom", errno);
            }
        }

        if (received == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        }

        struct icmphdr *hdr = (struct icmphdr *)((char *)buff + sizeof(struct iphdr));
        if (hdr->type != ICMP_ECHO) {
            // Simulate packet loss
            if (rand() < RAND_MAX * Random_Packet_Loss_Chance) {
                return 0;
            }

            break;
        }
    }

    if (g_stop_ping_loop) {
        return 0;
    }

    struct icmphdr *hdr = (struct icmphdr *)((char *)buff + sizeof(struct iphdr));
    if (hdr->type == ICMP_ECHOREPLY && hdr->un.echo.sequence == ctx->echo_sent) {
        ctx->reply_received += 1;
    }

    return received;
}

void PrintICMPPacket(Context *ctx, void *data, int size, double elapsed_ms) {
    struct iphdr *ip_header = (struct iphdr *)data;
    struct icmphdr *header = (struct icmphdr *)((char *)data + sizeof(struct iphdr));
    switch(header->type) {
    case ICMP_ECHO: break; // Ignore our own echo packets
    case ICMP_ECHOREPLY: {
        printf(
            "%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
            (int)(size - sizeof(struct iphdr)),
            "localhost", "127.0.0.1",
            header->un.echo.sequence, ip_header->ttl, elapsed_ms
        );
    } break;

    case ICMP_TIME_EXCEEDED: {
        ctx->error_num += 1;

        fprintf(stderr,
            "From %s: icmp_seq=%d Time to live exceeded\n",
            "127.0.0.1",
            ctx->echo_sent
        );
    } break;

    case ICMP_DEST_UNREACH: {
        ctx->error_num += 1;

        fprintf(stderr,
            "From %s: icmp_seq=%d Destination unreachable\n",
            "127.0.0.1",
            ctx->echo_sent
        );
    } break;

    case ICMP_SOURCE_QUENCH:
        ctx->error_num += 1;

        fprintf(stderr,
            "From %s: icmp_seq=%d Source quench\n",
            "127.0.0.1",
            ctx->echo_sent
        );
        break;

    case ICMP_PARAMETERPROB: {
        ctx->error_num += 1;

        fprintf(stderr,
            "From %s: icmp_seq=%d ICMP parameter problem\n",
            "127.0.0.1",
            ctx->echo_sent
        );
    } break;

    default: {
        ctx->error_num += 1;

        fprintf(stderr,
            "From %s: icmp_seq=%d Invalid ICMP packet type (%d)\n",
            "127.0.0.1",
            ctx->echo_sent,
            header->type
        );
    } break;

    // Not errors
    case ICMP_REDIRECT:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        break;
    }
}

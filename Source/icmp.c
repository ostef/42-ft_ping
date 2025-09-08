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
    PingPacket packet = {0};
    packet.header.type = ICMP_ECHO;
    packet.header.un.echo.id = htons(ctx->identifier);
    packet.header.un.echo.sequence = htons(ctx->echo_sent);

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
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                FatalErrorErrno("sendto", errno);
            }
        }

        if (sent == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        }

        break;
    }

    ctx->echo_sent += 1;

    return sent;
}

int ReceiveICMPPacket(Context *ctx, void *buff, int size) {
    int received = 0;
    while (!g_stop_ping_loop) {
        struct sockaddr_in dest_addr = ctx->dest_addr;
        socklen_t addrlen = sizeof(dest_addr);
        received = recvfrom(
            ctx->socket_fd,
            buff, size,
            MSG_DONTWAIT,
            (struct sockaddr *)&dest_addr, &addrlen
        );

        if (received < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                FatalErrorErrno("recvfrom", errno);
            }
        } else if (received == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        } else {
            struct iphdr *ip = (struct iphdr *)buff;
            if (ip->protocol != IPPROTO_ICMP) {
                continue;
            }

            struct icmphdr *hdr = (struct icmphdr *)((char *)buff + sizeof(struct iphdr));
            if (hdr->type == ICMP_ECHO) {
                continue;
            }

            if (hdr->type == ICMP_ECHOREPLY && ntohs(hdr->un.echo.id) != ctx->identifier) {
                continue;
            }

            if (hdr->type == ICMP_TIME_EXCEEDED || hdr->type == ICMP_DEST_UNREACH || hdr->type == ICMP_SOURCE_QUENCH || hdr->type == ICMP_PARAMETERPROB) {
                char *packet_data = (char *)(hdr + 1);
                struct iphdr *original_ip = (struct iphdr *)packet_data;
                struct icmphdr *original_icmp = (struct icmphdr *)(original_ip + 1);

                if (original_icmp->type != ICMP_ECHO || ntohs(original_icmp->un.echo.id) != ctx->identifier) {
                    continue;
                }
            }

            break;
        }
    }

    if (g_stop_ping_loop) {
        return 0;
    }

    struct icmphdr *hdr = (struct icmphdr *)((char *)buff + sizeof(struct iphdr));
    if (hdr->type == ICMP_ECHOREPLY) {
        ctx->reply_received += 1;
    }

    return received;
}

static void DumpIPHeader(struct iphdr *header) {
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];

    printf("IP Hdr Dump:\n");
    for (int i = 0; i < sizeof(*header); i += 2) {
        uint16_t bytes = *(uint16_t *)((uint8_t *)header + i);
        printf(" %.4x", ntohs(bytes));
    }
    printf("\n");
    printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");
    printf(" %1x ", header->version);
    printf(" %1x ", header->ihl);
    printf(" %02x ", header->tos);
    printf("%04x ", ntohs(header->tot_len));
    printf("%04x ", ntohs(header->id));
    printf("  %1x ", (ntohs(header->frag_off) & 0xe000) >> 13);
    printf("%04x ", ntohs(header->frag_off) & 0x1fff);
    printf(" %02x ", header->ttl);
    printf(" %02x ", header->protocol);
    printf("%04x ", ntohs(header->check));
    printf("%s ", inet_ntop(AF_INET, &header->saddr, src_addr, sizeof(src_addr)));
    printf(" %s ", inet_ntop(AF_INET, &header->daddr, dst_addr, sizeof(dst_addr)));

    int data_len = (header->ihl << 2) - sizeof(*header);
    uint8_t *data = (uint8_t *)header + sizeof(*header);
    for (int i = 0; i < data_len; i += 1) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void DumpICMPHeader(struct iphdr *ip, struct icmphdr *header) {
    printf("ICMP: type %u, code %u, size %u", header->type, header->code, ntohs(ip->tot_len) - (ip->ihl << 2));
    if (header->type == ICMP_ECHOREPLY || header->type == ICMP_ECHO) {
        printf(", id 0x%04x, seq 0x%04x", header->un.echo.id, ntohs(header->un.echo.sequence));
    }
    printf("\n");
}

void PrintICMPPacket(Context *ctx, void *data, int size, double elapsed_ms) {
    struct iphdr *ip_header = (struct iphdr *)data;
    if (ip_header->protocol != IPPROTO_ICMP) {
        printf("Not ICMP\n");
        return;
    }

    struct icmphdr *header = (struct icmphdr *)((char *)data + sizeof(struct iphdr));

    char received_from[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, received_from, sizeof(received_from));

    if (ip_header->saddr == ctx->dest_addr.sin_addr.s_addr) {
        printf("%d bytes from %s (%s): ", (int)(size - sizeof(struct iphdr)), ctx->dest_hostname, received_from);
    } else {
        printf("%d bytes from %s: ", (int)(size - sizeof(struct iphdr)), received_from);
    }

    switch(header->type) {
    case ICMP_ECHO: {
        printf("Echo\n");
    } break;

    case ICMP_ECHOREPLY: {
        printf("icmp_seq=%d ttl=%d time=%.2f ms\n", ntohs(header->un.echo.sequence), ip_header->ttl, elapsed_ms);
    } break;

    case ICMP_TIME_EXCEEDED: {
        ctx->error_num += 1;

        printf("Time to live exceeded\n");
        if (ctx->verbose) {
            char *packet_data = (char *)(header + 1);
            struct iphdr *original_ip = (struct iphdr *)packet_data;
            struct icmphdr *original_icmp = (struct icmphdr *)(original_ip + 1);

            DumpIPHeader(original_ip);
            DumpICMPHeader(original_ip, original_icmp);
        }
    } break;

    case ICMP_DEST_UNREACH: {
        ctx->error_num += 1;

        printf("Destination unreachable\n");
        if (ctx->verbose) {
            char *packet_data = (char *)(header + 1);
            struct iphdr *original_ip = (struct iphdr *)packet_data;
            struct icmphdr *original_icmp = (struct icmphdr *)(original_ip + 1);

            DumpIPHeader(original_ip);
            DumpICMPHeader(original_ip, original_icmp);
        }
    } break;

    case ICMP_SOURCE_QUENCH: {
        ctx->error_num += 1;

        printf("Source quench\n");
        if (ctx->verbose) {
            char *packet_data = (char *)(header + 1);
            struct iphdr *original_ip = (struct iphdr *)packet_data;
            struct icmphdr *original_icmp = (struct icmphdr *)(original_ip + 1);

            DumpIPHeader(original_ip);
            DumpICMPHeader(original_ip, original_icmp);
        }
    } break;

    case ICMP_PARAMETERPROB: {
        ctx->error_num += 1;

        printf("ICMP parameter problem\n");
        if (ctx->verbose) {
            char *packet_data = (char *)(header + 1);
            struct iphdr *original_ip = (struct iphdr *)packet_data;
            struct icmphdr *original_icmp = (struct icmphdr *)(original_ip + 1);

            DumpIPHeader(original_ip);
            DumpICMPHeader(original_ip, original_icmp);
        }
    } break;

    default: {
        ctx->error_num += 1;

        printf("Invalid ICMP packet type (%04x)\n", header->type);
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

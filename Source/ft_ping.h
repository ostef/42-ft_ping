#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

typedef struct
{
    char *dest_hostname;
    bool verbose;
    int ttl;
    float ping_interval_in_seconds;

    int socket_fd;
    struct sockaddr_in dest_addr;
    int echo_sent;
    int reply_received;
    int error_num;
} Context;

#define Ping_Packet_Size 64
#define Random_Packet_Loss_Chance 0.0

extern bool g_stop_ping_loop;

typedef struct __attribute ((packed))
{
    struct icmphdr header;
    char msg[Ping_Packet_Size - sizeof (struct icmphdr)];
} PingPacket;

void FatalError (const char *message, ...);
void FatalErrorErrno (const char *message, int err);
void FatalErrorEAI (const char *message, int err);

int SendICMPEchoPacket (Context *ctx);
int ReceiveICMPPacket (Context *ctx, void *buff, int size);
void PrintICMPPacket (Context *ctx, void *data, int size, double elapsed_ms);

void IntHandler (int);

void PingPong (Context *ctx);

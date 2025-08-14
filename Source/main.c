#include "ft_ping.h"

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://www.geeksforgeeks.org/ping-in-c/

void FatalError(const char *message, ...) {
    va_list va;

    fprintf(stderr, "Error: ");
    va_start(va, message);
    vfprintf(stderr, message, va);
    va_end(va);
    fprintf(stderr, "\n");

    exit(1);
}

void FatalErrorErrno(const char *message, int err) {
    fprintf(stderr, "Error: %s: %s\n", message, strerror(err));
    exit(1);
}

void FatalErrorEAI(const char *message, int err) {
    fprintf(stderr, "Error: %s: %s\n", message, gai_strerror(err));
    exit(1);
}

static void PrintUsage() {
    fprintf(stderr, "Usage\n");
    fprintf(stderr, "  ft_ping [options] <destination>\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  <destination>\t\tDNS name or IP address\n");
    fprintf(stderr, "  -t<number>\t\tdefine time to live\n");
    fprintf(stderr, "  -v\t\t\tverbose output\n");
}

static void HandleProgramArguments(Context *ctx, int argc, char **argv) {
    char option = 0;
    for (int i = 1; i < argc; i += 1) {
        if (argv[i][0] == '-') {
            char *option = argv[i] + 1;
            if (option[0] == 't') {
                option += 1;
                ctx->ttl = atoi(option);
            } else if (strcmp(option, "v") == 0) {
                ctx->verbose = true;
            } else if (strcmp(option, "?") == 0) {
                PrintUsage();
                exit(2);
            } else {
                FatalError("Unknown option '%s'", argv[i]);
            }
        } else {
            ctx->dest_hostname_arg = argv[i];
        }
    }

    if (!ctx->dest_hostname_arg) {
        FatalError("Destination address required");
    }
}

static void InitContext(Context *ctx) {
    ctx->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->socket_fd < 0) {
        FatalErrorErrno("socket", errno);
    }

    if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_TTL, &ctx->ttl, sizeof(ctx->ttl)) < 0) {
        FatalErrorErrno("setsockopt(IP_TTL)", errno);
    }

    int reuseaddr = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(SO_REUSEADDR)", errno);
    }

    int reuseport = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(SO_REUSEPORT)", errno);
    }

    // Lookup hostname
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    struct addrinfo *dest_addr_info = NULL;
    int res = getaddrinfo(ctx->dest_hostname_arg, NULL, &hints, &dest_addr_info);
    if (res != 0) {
        FatalErrorEAI("getaddrinfo", res);
    }

    if (dest_addr_info->ai_family != AF_INET) {
        freeaddrinfo(dest_addr_info);
        FatalError("Expected an IPV4 address");
    }

    if (dest_addr_info->ai_addrlen != sizeof(ctx->dest_addr)) {
        freeaddrinfo(dest_addr_info);
        FatalError("Expected an IPV4 address");
    }

    if (!inet_ntop(AF_INET, &dest_addr_info->ai_addr, ctx->dest_addr_str, sizeof(ctx->dest_addr_str))) {
        FatalErrorErrno("inet_ntop", errno);
    }

    memcpy(&ctx->dest_addr, dest_addr_info->ai_addr, sizeof(ctx->dest_addr));

    // Reverse DNS lookup
    res = getnameinfo(&ctx->dest_addr, sizeof(ctx->dest_addr), ctx->dest_hostname, sizeof(ctx->dest_hostname), NULL, 0, 0);
    if (res != 0) {
        freeaddrinfo(dest_addr_info);
        FatalErrorEAI("getnameinfo", res);
    }
}

int main(int argc, char **argv) {
    Context ctx = {0};
    ctx.ttl = 64;
    ctx.ping_interval_in_seconds = 1;

    signal(SIGINT, IntHandler);

    HandleProgramArguments(&ctx, argc, argv);
    InitContext(&ctx);
    PingPong(&ctx);
}

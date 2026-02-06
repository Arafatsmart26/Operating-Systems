#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <openssl/evp.h>
#include <stdint.h>

#define INPUT_SIZE 49

int server_fd;

static bool search_range(uint64_t start, uint64_t end, const uint8_t *target, uint64_t *found_value) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    unsigned char digest[32];

    for (uint64_t cur = start; cur <= end; cur++) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, &cur, sizeof(cur));
        EVP_DigestFinal_ex(ctx, digest, NULL);

        // check first 4 bytes first, if matches all 32
        uint32_t *a32 = (uint32_t*)digest;
        uint32_t *b32 = (uint32_t*)target;
        if (a32[0] != b32[0]) continue;
        if (a32[1] != b32[1]) continue;
        if (a32[2] != b32[2]) continue;
        if (a32[3] != b32[3]) continue;
        if (a32[4] != b32[4]) continue;
        if (a32[5] != b32[5]) continue;
        if (a32[6] != b32[6]) continue;
        if (a32[7] != b32[7]) continue;

        *found_value = cur;
        EVP_MD_CTX_free(ctx);
        return true;
    }

    EVP_MD_CTX_free(ctx);
    return false;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    struct sockaddr_in addr;
    char buffer[1024];
    int client_fd;
    socklen_t addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "ERROR: Failed to create socket!\n");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ERROR: Failed to bind!\n");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 4096) < 0) {
        fprintf(stderr, "ERROR: Failed to listen!\n");
        close(server_fd);
        return 1;
    }

    printf("Listening on port %d...\n", port);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
        if (client_fd < 0) {
            fprintf(stderr, "ERROR: Failed to accept!\n");
            close(server_fd);
            return 1;
        }

        int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            printf("Client disconnected.\n");
            close(client_fd);
            continue;
        }

        if (bytes != INPUT_SIZE) {
            printf("ERROR: Invalid packet length, expected %d bytes, got %d\n",
                   INPUT_SIZE, bytes);
            close(client_fd);
            continue;
        }

        uint8_t target_hash[32];
        memcpy(target_hash, buffer, 32);

        uint64_t start_net, end_net;
        memcpy(&start_net, &buffer[32], 8);
        memcpy(&end_net,   &buffer[40], 8);

        uint64_t start = be64toh(start_net);
        uint64_t end   = be64toh(end_net);

        uint64_t found_value = 0;
        bool found = search_range(start, end, target_hash, &found_value);

        if (found) {
            uint64_t answer_net = htobe64(found_value);
            send(client_fd, &answer_net, sizeof(answer_net), 0);
        } else {
            fprintf(stderr, "ERROR: Not found in range.\n");
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}

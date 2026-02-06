#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <openssl/evp.h>
#include <stdint.h>


// Arbitrary batch size, not too big, not too small
#define BATCH_SIZE 64
#define INPUT_SIZE 49

int server_fd;

// Hashing in batches, requires containers to read from and write to
static inline void sha256_batch(
    const unsigned char inputs[][8],
    unsigned char outputs[][32],
    int count
) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    for (int i = 0; i < count; i++) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, inputs[i], 8);
        EVP_DigestFinal_ex(ctx, outputs[i], NULL);
    }

    EVP_MD_CTX_free(ctx);
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
            printf("Client disconnected or recv error!\n");
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

        unsigned char batch_inputs[BATCH_SIZE][8];
        unsigned char batch_outputs[BATCH_SIZE][32];

        bool found = false;
        uint64_t found_value = 0;
        uint64_t cur = start;

        while (cur <= end) {
            int count = 0;
            for (int i = 0; i < BATCH_SIZE && cur <= end; i++, cur++) {
                memcpy(batch_inputs[i], &cur, 8);
                count++;
            }

            sha256_batch(batch_inputs, batch_outputs, count);

            for (int i = 0; i < count; i++) {
                if (memcmp(batch_outputs[i], target_hash, 32) == 0) {
                    found = true;
                    found_value = cur - (count - i);
                    break;
                }
            }

            if (found) break;
        }

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

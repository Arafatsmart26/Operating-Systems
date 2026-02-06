#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <stdint.h>

#define CACHE_SIZE 1024
#define INPUT_SIZE 49

int server_fd;

// Zero defaulting to invalid entry
struct cache_entry {
    bool valid;
    uint8_t hash[32];
    uint64_t value;
};

// Global cache storage as a preallocated array
static struct cache_entry cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static int cache_next_index = 0;

// Thread safe cache lookups
bool cache_lookup(const uint8_t hash[32], uint64_t *value_out)
{
    bool ok = false;
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i].valid && memcmp(cache[i].hash, hash, 32) == 0) {
            *value_out = cache[i].value;
            ok = true;
            break;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
    return ok;
}

// Thread saft cache updates
void cache_insert(const uint8_t hash[32], uint64_t value)
{
    pthread_mutex_lock(&cache_mutex);
    cache[cache_next_index].valid = true;
    memcpy(cache[cache_next_index].hash, hash, 32);
    cache[cache_next_index].value = value;
    cache_next_index = (cache_next_index + 1) % CACHE_SIZE;
    pthread_mutex_unlock(&cache_mutex);
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

    for (int i = 0; i < CACHE_SIZE; i++) cache[i].valid = false;

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

        buffer[bytes] = '\0';

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

        uint64_t cached_value;
        if (cache_lookup(target_hash, &cached_value) &&
            cached_value >= start && cached_value <= end)
        {
            uint64_t net = htobe64(cached_value);
            send(client_fd, &net, sizeof(net), 0);
            close(client_fd);
            continue;
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            fprintf(stderr, "ERROR: Failed to create SHA context\n");
            close(client_fd);
            continue;
        }

        unsigned char digest[32];
        bool found = false;
        uint64_t found_value = 0;

        for (uint64_t cur = start; cur <= end; cur++) {
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, &cur, 8);
            EVP_DigestFinal_ex(ctx, digest, NULL);

            if (memcmp(digest, target_hash, 32) == 0) {
                found = true;
                found_value = cur;
                break;
            }
        }

        EVP_MD_CTX_free(ctx);

        if (found) {
            cache_insert(target_hash, found_value);
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

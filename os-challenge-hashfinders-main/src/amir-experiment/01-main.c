#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/evp.h>
#include <stdint.h>

// Could be greater depending on physical threads of hardware
#define MAX_THREADS 8
#define INPUT_SIZE 49

int server_fd;

// Very important for global state as threads pass through the range of numbers
static atomic_bool found_flag = false;
static atomic_ullong found_value_atomic = 0;

// All workers need start-end range and what the target hash is
typedef struct {
    uint64_t start;
    uint64_t end;
    const uint8_t *target_hash;
} job_t;

// Given the range, split it up to workers almost equally
static inline void split_range(uint64_t start, uint64_t end,
                               int n, job_t jobs[], const uint8_t *hash)
{
    uint64_t total = (end >= start) ? (end - start) + 1 : 0;

    if (total == 0) {
        for (int i = 0; i < n; i++) {
            jobs[i].start = 1;
            jobs[i].end   = 0;
            jobs[i].target_hash = hash;
        }
        return;
    }

    uint64_t base = total / n;
    uint64_t extra = total % n;
    uint64_t cur = start;

    for (int i = 0; i < n; i++) {
        uint64_t size = base + (i < extra ? 1 : 0);

        if (size == 0) {
            jobs[i].start = 1;
            jobs[i].end   = 0;
        } else {
            jobs[i].start = cur;
            jobs[i].end   = cur + size - 1;
            cur += size;
        }

        jobs[i].target_hash = hash;
    }
}

void *worker(void *arg)
{
    job_t *job = (job_t *)arg;

    if (job->start > job->end)
        return NULL;

    const uint8_t *target = job->target_hash;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return NULL;

    unsigned char digest[32];

    // iterating over the subrange
    for (uint64_t cur = job->start; cur <= job->end && !atomic_load(&found_flag); cur++) {

        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, &cur, 8);
        EVP_DigestFinal_ex(ctx, digest, NULL);

        if (memcmp(digest, target, 32) == 0) {
            atomic_store(&found_value_atomic, cur);
            atomic_store(&found_flag, true);
            break;
        }
    }

    EVP_MD_CTX_free(ctx);
    return NULL;
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

        atomic_store(&found_flag, false);
        atomic_store(&found_value_atomic, 0);

        pthread_t threads[MAX_THREADS];
        job_t jobs[MAX_THREADS];

        split_range(start, end, MAX_THREADS, jobs, target_hash);

        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_create(&threads[i], NULL, worker, &jobs[i]);
        }

        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (atomic_load(&found_flag)) {
            uint64_t found_val = atomic_load(&found_value_atomic);
            uint64_t answer_net = htobe64(found_val);
            send(client_fd, &answer_net, sizeof(answer_net), 0);
        } else {
            fprintf(stderr, "ERROR: Not found in range.\n");
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}

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

#define MAX_THREADS 8
#define BATCH_SIZE 64
#define CACHE_SIZE 1024
#define INPUT_SIZE 49

int server_fd;

struct cache_entry {
    bool valid;
    uint8_t hash[32];
    uint64_t value;
};

static struct cache_entry cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static int cache_next_index = 0;

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

void cache_insert(const uint8_t hash[32], uint64_t value)
{
    pthread_mutex_lock(&cache_mutex);
    cache[cache_next_index].valid = true;
    memcpy(cache[cache_next_index].hash, hash, 32);
    cache[cache_next_index].value = value;
    cache_next_index = (cache_next_index + 1) % CACHE_SIZE;
    pthread_mutex_unlock(&cache_mutex);
}

static atomic_bool found_flag = false;
static atomic_ullong found_value_atomic = 0;

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

typedef struct {
    uint64_t start;
    uint64_t end;
    const uint8_t *target_hash;
} job_t;

static inline void split_range(uint64_t start, uint64_t end,
                               int n, job_t jobs[], const uint8_t *hash)
{
    uint64_t total = (end >= start) ? (end - start) + 1 : 0;
    if (total == 0) {
        for (int i = 0; i < n; i++) {
            jobs[i].start = 1;
            jobs[i].end = 0;
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
            jobs[i].end = 0;
        } else {
            jobs[i].start = cur;
            jobs[i].end = cur + size - 1;
            cur += size;
        }
        jobs[i].target_hash = hash;
    }
}

void *worker(void *arg)
{
    job_t *job = (job_t *)arg;

    if (job->start > job->end) return NULL;

    unsigned char batch_inputs[BATCH_SIZE][8];
    unsigned char batch_outputs[BATCH_SIZE][32];

    uint64_t cur = job->start;
    const uint8_t *target = job->target_hash;

    while (cur <= job->end && !atomic_load(&found_flag)) {
        int count = 0;
        for (int i = 0; i < BATCH_SIZE && cur <= job->end; i++, cur++) {
            memcpy(batch_inputs[i], &cur, 8);
            count++;
        }

        if (count == 0) break;

        sha256_batch(batch_inputs, batch_outputs, count);

        for (int i = 0; i < count; i++) {
            if (atomic_load(&found_flag)) break; /* another thread found it */
            if (memcmp(batch_outputs[i], target, 32) == 0) {
                uint64_t value = (cur - (count - i));
                atomic_store(&found_value_atomic, (unsigned long long)value);
                atomic_store(&found_flag, true);
                return NULL;
            }
        }
    }

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
            printf("ERROR: Invalid packet length, expected %d bytes, got %d\n", INPUT_SIZE, bytes);
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
            unsigned long long found_val = atomic_load(&found_value_atomic);
            cache_insert(target_hash, (uint64_t)found_val);

            uint64_t answer_net = htobe64((uint64_t)found_val);
            send(client_fd, &answer_net, sizeof(answer_net), 0);
        } else {
            fprintf(stderr, "ERROR: Not found in range.\n");
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}


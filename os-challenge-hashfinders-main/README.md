# OS-Challenge Final Assignment Report
```verbatim
Course: 02159 Operating Systems
Group:  Hashfinders
Group members: Arafat Hossain (s235482) , Miguel Perpiñá (s251780), Amirkhon Alimov (s204743)
Date: 04.12.2025
```

# Introduction

This project introduces the design and implementation of a TCP-based server capable of computing reverse hashes for requested numerical inputs.
The system is built to efficiently handle multiple incoming requests in rapid succession, with a strong focus on minimizing response time.

To achieve high performance, the server incorporates several optimization techniques, which will be examined in detail later in the report.
These techniques are aimed at improving throughput, reducing latency, and ensuring that the system scales effectively under increased load.

Throughout the project, particular attention is given to both performance and memory efficiency.
The goal is not only to deliver fast results but also to maintain a lightweight and resource-conscious design that performs well across different operating conditions.

# Build
## How to build and run the project
TCP server implementation for reverse hashing by hashfinders:
```console
    git clone https://github.com/dtu-ese/os-challenge-common.git    # This is common repo everyone has access to
    cd os-challenge-common/x86-64
    vagrant up
    vagrant ssh client  # Open the client in a new tab
    vagrant ssh server  # Open the server in a new tab
```
In the server tab:
```console
    git clone https://gitlab.gbar.dtu.dk/s204743/os-challenge-hashfinders.git
    cd os-challenge-hashfinders
    make
    ./server 5003
```
In the client tab:
```console
    cd os-challenge-common
    ./run-client-milestone.sh
```
# Setup and Environment
Our development environment varied depending on each group member’s laptop. Two members worked on Windows machines, while one used Linux.

On both systems, we installed Oracle VirtualBox and Vagrant, then set up the OS Challenge environment using the Vagrantfile from the `x86_64` folder of the os-challenge-common repository.
This setup created two Ubuntu-based virtual machines: one acting as the server and the other as the client.

During setup, we faced several issues on Windows, including VirtualBox detection problems, terminal input errors, Windows file indexing and newline formatting.
To avoid these disruptions, we switched to the Linux setup, where the Vagrant environment ran with minimal issues.
Primary error was hardware virtualization which was simply turned off for Vagrant to run with no problems.
Once everything was running correctly, we shared the working configuration and code with the rest of the group through GitLab.

We heavily relied on group/pair programming setup, where either in person or in a group call we collaborated on the same piece of code at the same time, with a single person taking charge for each experiment.

# Implementation
The project was developed in two stages: Milestone implementation and Final implementation.
Milestone implementation concerns itself with guaranteeing 100% reliability with a naive brute-force approach.
It is structured as a simple TCP server that is bound to a port and clients connect to, then the input is parsed into its components.
```c
int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
if (bytes <= 0) {
    printf("Client disconnected!\n");
    break;
}

buffer[bytes] = '\0';

#define INPUT_SIZE 49
if (bytes != INPUT_SIZE) {
    printf("ERROR: Invalid packet length, expected %d bytes\n", INPUT_SIZE);
    continue;
}

uint8_t hash[32];
memcpy(hash, buffer, 32);

uint64_t start_net, end_net;
memcpy(&start_net, &buffer[32], 8);
memcpy(&end_net, &buffer[40], 8);

uint64_t start = be64toh(start_net);
uint64_t end   = be64toh(end_net);
uint8_t p = buffer[48];
```
Then, the server iterates on values from `start` to `end` and each hash value is calculated and compared to the requested `hash`.
```c
uint64_t current = htole64(start);
unsigned char buf[8];
bool found = false;
while (current <= end) {
    memcpy(buf, &current, 8);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(buf, sizeof(buf), digest);

    if (memcmp(hash, digest, 32) == 0) {
        current = htobe64(current);
        send(client_fd, &current, sizeof(current), 0);
        found = true;
        break;
    }

    current += 1;
}
```
Once, the intended number is found the server sends it back to the client.

# Experiments
All experiments have been augumentations of the Milestone stage project with one improvement at a time.
Then, an amalgamated version tested with all improvements together.

## Amir
### Multi-Threading
#### Premise
Multi-threading was implemented using the `pthread.h` library, a struct of jobs and worker functions have been implemented as follows:
```c
// All workers need start-end range and what the target hash is
typedef struct {
    uint64_t start;
    uint64_t end;
    const uint8_t *target_hash;
} job_t;
```
```c
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
```

Each job just represents a range of the number space for a worker to search, with global atomic flags indicating if a given worker found it or not.

In the project, it is split into 8 threads, if each worked at maximum efficiency with no collusions and ecen performance, on average performance increase of 8 times should be expected.

Factors like, cache misses, memmory bandwith limitations, and poor thread scheduling may result in less performance than that, speed up of 8x should not be expected. 

#### Results
Comparison results are given in the table below:

|                 |  1           |  2           |  3           |  4           |  5           |  Average     |  MIN         |  MAX         |
|    ---          | ---          | ---          | ---          | ---          | ---          |    ---       |  ---         |  ---         |
| Milestone       | 1,425,628.00 | 1,314,958.00 | 1,417,719.00 | 1,221,083.00 | 1,383,811.00 | 1,352,639.80 | 1,221,083.00 | 1,425,628.00 |
| Multi-Threading | 298,700.00  | 308,714.00 | 331,748.00   | 345,581.00   | 360,955.00   | 329,139.60   | 298,700.00   | 360,955.00   |

As evident, per the trials and averages above, there is an average of `4.11` times improvement from multi-threading.
Which is more than two times smaller performance improvement than theoretical maximum, but it is definetely within reason.

### Byte time comparison
#### Premise
In the Milestone implementation `memcmp` was used to compare hashes which resulted in comparions of 32-byte hashes in whole.
Another approach is to compare 4-bytes at a time with simple integer comparison as follows:
```c
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
```

This way, great many comparisons are shortcut since the probability of the first 4 bytes of two hashes is the same is only $\frac{1}{2^{32}} \approx 2.33 \times 10^{-10}$.

Meaning, a quick `int32_t` comparison is extremely efficient both in operations and cutting down the hash comparison.

#### Results
|                      |  1           |  2           |  3           |  4           |  5           |  Average     |  MIN         |  MAX         |
|    ---               | ---          | ---          | ---          | ---          | ---          |    ---       |  ---         |  ---         |
| Milestone            | 1,425,628.00 | 1,314,958.00 | 1,417,719.00 | 1,221,083.00 | 1,383,811.00 | 1,352,639.80 | 1,221,083.00 | 1,425,628.00 |
| Byte time comparison | 865,204.00   | 761,033.00   | 811,023.00   | 799,133.00   | 813,021.00   | 809,882.80   | 761,033.00   | 865,204.00   |

As evident, per the trials and averages above, there is an average of `1.67` times improvement from byte time comparison.
Main limitation for this approach is that hashes are still sequentually calculated for the entire `start` to `end` range.

## Arafat
### Batch hashing
#### Premise
In this part we designed and later implemented a vectorized hashing experiment.
The purpose for this was to process many SHA-256 hash computations efficiently.
They had to use batching while communicating over a simple TCP server.
This simulates a modern systems handling parallel workloads which is a concept that's closely related to OS-system managing CPU tasks, concurrency and efficient resource utilization

Here is an overview of the program.
The program of TCP server listens to ports and waits for clients to target a hash (32 bytes), start value (8 bytes, big-indian) and an end value (8 bytes, big-endian).
Later it will scan all possible 8-bytes values that's within range and hashing each for checking. If any targeted hash matches, when found it will return a matching value to the client. 

In the section, we are creating a TCP socket. It binds to a specific port and listens for incoming clients connection and uses the standard POSIX socket API for networking. 

After we have a SHA-256 Batch function, it computes for each iteration of 64 inputs while the OpenSSL API has no real support SIMD (vectorized) operation.
The batching multiple inputs of each iteration will improve cache locality and reduce to minimum per-call setup overhead.
```c
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
```

For the Main loop, it accepts the incoming connections and processes the search range.
It will read a batch of candidates into the memory and hashes them all for checks and matches against a hash target.
Then the loop will continue until there is either a match or none at the end of the search range.  

#### Results
|            |  1           |  2           |  3           |  4           |  5           | Average      | MIN          | MAX          |
| ---        | ---          | ---          | ---          | ---          | ---          | ---          | ---          | ---          |
| Milestone  | 1,425,628.00 | 1,314,958.00 | 1,417,719.00 | 1,221,083.00 | 1,383,811.00 | 1,352,639.80 | 1,221,083.00 | 1,425,628.00 |
| Caching    | 350,288.00   | 381,123.00   | 400,113.00   | 320,133.00   | 381,811.00   | 366,693.60   | 320,133.00   | 400,113.00   |

When a match is found it will respond to client, if not the server will print “not found”.
our hashing is 3,7 times faster.



## Miguel
### Caching
This experiment aimed to reduce redundant computation caused by multiple repeated hash requests.
The server receives a SHA-256 hash and a search range from the client. Normally, it would brute-force all values in this range until the correct one is found, which is computationally expensive. We implemented a cache to store previously solved hash-value pairs.
Before performing the actual brute-force computation, the server first checks if the hash received is already present in the cache. In case it finds such a cached value and this lies within the range that has been requested, the server returns immediately with the cached result without recomputing the hash. If the hash is not found, the server performs the computation and then stores the result in the cache for future requests.
This optimization reduces CPU usage and response time for repeated requests, showcasing the advantages of caching in system-level applications.

#### Premise
```c
struct cache_entry {
    bool valid;
    uint8_t hash[32];
    uint64_t value;  // valor en orden de host
};
 This structure defines a single cache entry used by the server.
Every entry stores a 32-byte SHA-256 hash (hash), the numeric value that produces this hash (value), and a validity flag (valid).
The server maintains an in-memory array of such entries that serves as a simple in-memory cache of hash challenges that have already been solved.
static struct cache_entry cache[CACHE_SIZE];
```
```c
bool cache_lookup(const uint8_t hash[32], uint64_t *value_out)
{
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i].valid && memcmp(cache[i].hash, hash, 32) == 0) {
            *value_out = cache[i].value;
            return true;
        }
    }
    return false;
}
This function will search the cache for a given SHA-256 hash.
It iterates over all the cache entries and returns, through value_out, the associated value when a valid entry has an equal stored hash as requested. It then reports success by returning true.

When no entry with a matching key is found, the function returns false, indicating a cache miss and forcing the server to compute the result normally.
```
```c
void cache_insert(const uint8_t hash[32], uint64_t value)
{
    static int next_index = 0;
    cache[next_index].valid = true;
    memcpy(cache[next_index].hash, hash, 32);
    cache[next_index].value = value;
    next_index = (next_index + 1) % CACHE_SIZE;
}
This method inserts a new result into the cache after the server has computed it.

It uses a simple round-robin strategy: the new hash and value are stored at the position indicated by next_index, and this index is then advanced modulo CACHE_SIZE.
This keeps the implementation simple and ensures that the cache is constantly refreshed with the most recently used results.
```
```c
 uint64_t cached_value;
        if (cache_lookup(hash, &cached_value) &&
            cached_value >= start && cached_value <= end) {

            uint64_t net = htobe64(cached_value);
            send(client_fd, &net, sizeof(net), 0);
            // opcional: printf("Cache HIT\n");
            continue;  // pasamos al siguiente cliente
        }
The server checks whether the requested hash has been already solved, by calling cache_lookup before entering into the expensive brute-force loop. 
If the hash is found in the cache, and the stored value lies within the requested range, the server immediately converts it to network byte order and sends it back to the client. 
In this case, the server avoids the brute-force search altogether, illustrating the principal advantage of the caching mechanism.

#### Results
|            |  1           |  2           |  3           |  4           |  5           | Average      | MIN          | MAX          |
| ---        | ---          | ---          | ---          | ---          | ---          | ---          | ---          | ---          |
| Milestone  | 1,425,628.00 | 1,314,958.00 | 1,417,719.00 | 1,221,083.00 | 1,383,811.00 | 1,352,639.80 | 1,221,083.00 | 1,425,628.00 |
| Caching    | 951,724.00   | 684,930.00   | 892,125.00   | 719,220.00   | 894,323.00   | 828,464.40   | 684,930.00   | 951,724.00   |

As can be seen from the trials and averages above, caching provides an average
performance improvement of 1.63 times compared to the Milestone implementation.

The main advantage of caching shows up when there are repeated hash requests.
With them, it is possible to reuse previously computed results, avoiding unnecessary
brute-force computation. However, when requests are mostly unique, the impact
The concept of caching is limited.

# Evaluation
Final implementation encompasses all experimental features together and presents results as follows:
|           |  1           |  2           |  3           |  4           |  5           |  Average     |  MIN         |  MAX         |
|    ---    | ---          | ---          | ---          | ---          | ---          |    ---       |  ---         |  ---         |
| Milestone | 1,425,628.00 | 1,314,958.00 | 1,417,719.00 | 1,221,083.00 | 1,383,811.00 | 1,352,639.80 | 1,221,083.00 | 1,425,628.00 |
| Final     | 80,671.00    | 76,067.00    | 88,071.00    | 80,064.00    | 90,849.00    | 80,624.40    | 76,067.00    | 90,849.00    |

Clearly, the final solution performs significantly better than the Milestone implementation by `15.68` times.
This is mainly attributed to the synergy between batch hashing and multi-threading.

# Conclusions
The project successfully demonstrates the design and implementation of a high-performance TCP-based server for reverse hash computation.
Through systematic experimentation, we identified and applied several optimization techniques multi-threading, byte-wise hash comparison, batch hashing, and caching that significantly improved performance over the naive Milestone implementation.

Our results show that the final implementation achieved an average speedup of over 15 times compared to the Milestone version, highlighting the effectiveness of combining multiple optimization strategies.
Multi-threading provided substantial concurrency gains, while byte-wise comparison and batch hashing further reduced computational overhead.

Overall, the project illustrates the importance of careful performance analysis, incremental improvements, and efficient resource utilization in the design of scalable systems.
The resulting server is not only fast and reliable but also demonstrates how well-structured optimization can transform a simple brute-force approach into a highly efficient solution.

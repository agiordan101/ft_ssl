#include "ft_ssl.h"

/*
    SHA-256 algorithm
*/

static void                 init_sha(t_sha *sha, Mem_8bits *chunks, Long_64bits chunksSz)
{
    sha->chunks = chunks;
    sha->chunksSz = chunksSz;    
    sha->hash[0] = 0x6a09e667;
    sha->hash[1] = 0xbb67ae85;
    sha->hash[2] = 0x3c6ef372;
    sha->hash[3] = 0xa54ff53a;
    sha->hash[4] = 0x510e527f;
    sha->hash[5] = 0x9b05688c;
    sha->hash[6] = 0x1f83d9ab;
    sha->hash[7] = 0x5be0cd19;

    Word_32bits k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    ft_memcpy(sha->k, k, 64 * WORD32_ByteSz);
}

static inline Word_32bits   Ch(Word_32bits x, Word_32bits y, Word_32bits z)
{
    return (x & y) ^ (~x & z);
}

static inline Word_32bits   Maj(Word_32bits x, Word_32bits y, Word_32bits z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline Word_32bits   Sum0(Word_32bits x)
{
    return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22);
}

static inline Word_32bits   Sum1(Word_32bits x)
{
    return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25);
}

static inline Word_32bits   Sigma0(Word_32bits x)
{
    return rotR(x, 7) ^ rotR(x, 18) ^ (x >> 3);
}

static inline Word_32bits   Sigma1(Word_32bits x)
{
    return rotR(x, 17) ^ rotR(x, 19) ^ (x >> 10);
}

static void hash_chunk(t_sha *sha, Word_32bits *chunk)
{
    Word_32bits words[64];  // Chunk msg
    Word_32bits t1;
    Word_32bits t2;
    Word_32bits a = sha->hash[0];
    Word_32bits b = sha->hash[1];
    Word_32bits c = sha->hash[2];
    Word_32bits d = sha->hash[3];
    Word_32bits e = sha->hash[4];
    Word_32bits f = sha->hash[5];
    Word_32bits g = sha->hash[6];
    Word_32bits h = sha->hash[7];

    ft_memcpy(words, chunk, CHUNK_ByteSz);

    for (int i = 0; i < 64; i++)
    {
        // Initialize words (16 from chunk and 48 made with)
        if (i < 16)
            endianReverse((Mem_8bits *)&words[i], WORD32_ByteSz); // Big endian to little endian
        else
            words[i] = Sigma1(words[i - 2]) + words[i - 7] + Sigma0(words[i - 15]) + words[i - 16];

        t1 = h + Sum1(e) + Ch(e, f, g) + sha->k[i] + words[i];
        t2 = Sum0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    sha->hash[0] += a;
    sha->hash[1] += b;
    sha->hash[2] += c;
    sha->hash[3] += d;
    sha->hash[4] += e;
    sha->hash[5] += f;
    sha->hash[6] += g;
    sha->hash[7] += h;
}

Mem_8bits   *sha256(Mem_8bits **plaintext, Long_64bits ptByteSz, Long_64bits *hashByteSz, e_flags way)
{
    t_sha   sha;

    md_padding(plaintext, &ptByteSz, 1);
    init_sha(&sha, *plaintext, ptByteSz);

    // printBits(chunks, CHUNK_ByteSz);
    Word_32bits *chunks = (Word_32bits *)sha.chunks;
    Word_32bits *chunk = chunks;
    while (chunk < chunks + sha.chunksSz / WORD32_ByteSz)
    {
        hash_chunk(&sha, chunk);
        chunk += CHUNK_ByteSz / WORD32_ByteSz;
    }

    // Restore right endianness order
    for (Word_32bits *tmp = (Word_32bits *)sha.hash; tmp < sha.hash + SHA256_WordSz; tmp += 1)
        endianReverse((Mem_8bits *)tmp, WORD32_ByteSz);

    (void)way;
    if (hashByteSz)
        *hashByteSz = SHA256_byteSz;
    return ft_memdup((Mem_8bits *)sha.hash, SHA256_byteSz);
}

/*
    SHA-256 related functions
*/

inline void sha256_xor_8bits(Mem_8bits *sha1, Mem_8bits *sha2, Mem_8bits **result)
{
    for (uint i = 0; i < SHA256_byteSz; i++)
        (*result)[i] = sha1[i] ^ sha2[i];
}

inline void sha256_print(Mem_8bits *sha)
{
    printf("\nSHA256 HASH (len=%ld) >%s<\n", SHA256_byteSz, sha);
    for (Word_32bits *tmp = (Word_32bits *)sha; tmp < (Word_32bits *)sha + SHA256_WordSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    printf("\n");
}

#include "ft_ssl.h"

void    init_sha(t_sha *sha, Mem_8bits *chunks, Long_64bits chunksSz)
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
    ft_memcpy(sha->k, k, 64 * WORD_ByteSz);

    // Word_32bits constants[64] = {
    //     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    //     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    //     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    //     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    // };
    // ft_memcpy(sha->constants, constants, 64 * WORD_ByteSz);
}

inline Word_32bits Ch(Word_32bits x, Word_32bits y, Word_32bits z)
{
    return (x & y) ^ (~x & z);
}

inline Word_32bits Maj(Word_32bits x, Word_32bits y, Word_32bits z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline Word_32bits Sum0(Word_32bits x)
{
    return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22);
}

inline Word_32bits Sum1(Word_32bits x)
{
    return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25);
}

inline Word_32bits Sigma0(Word_32bits x)
{
    return rotR(x, 7) ^ rotR(x, 18) ^ (x >> 3);
}

inline Word_32bits Sigma1(Word_32bits x)
{
    return rotR(x, 17) ^ rotR(x, 19) ^ (x >> 10);
}

static void    hash_chunk(t_sha *sha, Word_32bits *chunk)
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
            endianReverse((Mem_8bits *)&words[i], WORD_ByteSz); // Big endian to little endian
        else
        {
            words[i] = Sigma1(words[i - 2]) + words[i - 7] + Sigma0(words[i - 15]) + words[i - 16];
            // printf("words[%d - 2]: %x\n", i, words[i - 2]);
            // printf("words[%d - 7]: %x\n", i, words[i - 7]);
            // printf("words[%d - 15]: %x\n", i, words[i - 15]);
            // printf("words[%d - 16]: %x\n", i, words[i - 16]);
            // printf("Sigma1(words[%d - 2]): %x\n", i, Sigma1(words[i - 2]));
            // printf("Sigma0(words[%d - 15]): %x\n", i, Sigma0(words[i - 15]));
        }
        // printf("word[%d]: %x\n", i, words[i]);

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

void    sha256(t_hash *hash)
{
    t_sha   sha;
    init_sha(&sha, (Mem_8bits *)hash->msg, (Long_64bits)hash->len);

    // printBits(sha.chunks, sha.chunksSz);
    padding(&sha.chunks, &sha.chunksSz, 1);

    // printf("CHUNK_ByteSz: %ld bytes\n", CHUNK_ByteSz);
    Word_32bits *chunks = (Word_32bits *)sha.chunks;
    // printBits(chunks, CHUNK_ByteSz);

    Word_32bits *chunk = chunks;
    while (chunk < chunks + sha.chunksSz / WORD_ByteSz)
    {
        hash_chunk(&sha, chunk);
        chunk += CHUNK_ByteSz / WORD_ByteSz;
    }

    ft_memcpy(hash->hash, sha.hash, 8 * WORD_ByteSz);
    for (int i = 0; i < 8; i++) // little endian to big endian
        endianReverse((Mem_8bits *)&hash->hash[i], WORD_ByteSz);

    // printBits(sha.chunks, sha.chunksSz);
}

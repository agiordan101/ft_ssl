#include "ft_ssl.h"

// Concatenate X & Y, return hash.
static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen);

size_t hmac_sha256(const void* key,
                   const size_t keylen,
                   const void* data,
                   const size_t datalen,
                   void* out,
                   const size_t outlen) {
  unsigned char k[SHA256_byteSz];
  unsigned char k_ipad[SHA256_byteSz];
  unsigned char k_opad[SHA256_byteSz];
  unsigned char ihash[SHA256_byteSz];
  unsigned char ohash[SHA256_byteSz];
  size_t sz;
  int i;

  memset(k, 0, sizeof(k));
  memset(k_ipad, 0x36, SHA256_byteSz);
  memset(k_opad, 0x5c, SHA256_byteSz);

  if (keylen > SHA256_byteSz) {
    // If the key is larger than the hash algorithm's
    // block size, we must digest it first.
    sha256(key, keylen, k, sizeof(k));
  } else {
    memcpy(k, key, keylen);
  }
  // printMemHex((Mem_8bits *)&k, SHA256_byteSz, "Key after padding");

  for (i = 0; i < SHA256_byteSz; i++) {
    k_ipad[i] ^= k[i];
    k_opad[i] ^= k[i];
  }

  // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
  //      `H(K XOR opad, H(K XOR ipad, data))`
  H(k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
  // printMemHex((Mem_8bits *)&ihash, SHA256_byteSz, "ihash");
  H(k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));
  // printMemHex((Mem_8bits *)&ohash, SHA256_byteSz, "ohash");

  sz = (outlen > SHA256_byteSz) ? SHA256_byteSz : outlen;
  memcpy(out, ohash, sz);
  return sz;
}

static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen)
{
  void* result;
  size_t buflen = (xlen + ylen);
  unsigned char* buf = (unsigned char *)malloc(buflen);
//   uint8_t* buf = (uint8_t*)malloc(buflen);

  memcpy(buf, x, xlen);
  memcpy(buf + xlen, y, ylen);

  unsigned char *sha256_out = sha256((Mem_8bits **)&buf, buflen, NULL, 0);
  memcpy(out, sha256_out, SHA256_byteSz);

  free(buf);
  return result;
}

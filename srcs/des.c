#include "ft_ssl.h"

static void init_vars(t_cipher *cipher)
{
    // printBits(cipher->salt, 8);
    printf("ssl.cipher.key: %s\n", ssl.cipher.key);
    printf("ssl.cipher.password: %s\n", ssl.cipher.password);
    printf("ssl.cipher.salt: %s\n", ssl.cipher.salt);
    printf("ssl.cipher.vector: %s\n", ssl.cipher.vector);
    
    Long_64bits tmp = ft_strtoHex(cipher->salt);
    printBits(&tmp, LONG64_ByteSz);
    ft_printHex(tmp);
    printf("tmp: %lx\n", tmp);

    cipher->salt = ft_hexToBin(tmp, LONG64_ByteSz);
    cipher->saltSz = ft_strlen(cipher->salt);
    printBits(cipher->salt, cipher->saltSz);

    exit(0);

    if (cipher->salt)
    {
        padXbits(&cipher->salt, &cipher->saltSz, KEY_byteSz); // To move in des algorithm
        printBits(cipher->salt, cipher->saltSz);
        
        printf("ssl.cipher.salt: %s\n", ssl.cipher.salt);
    }
}

void    des(t_hash *hash)
{
    init_vars(&ssl.cipher);
    pbkdf2_sha256(ssl.cipher.password, ssl.cipher.salt, 0);
}

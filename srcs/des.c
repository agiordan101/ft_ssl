#include "ft_ssl.h"

static void init_vars(t_cipher *cipher)
{
    // printBits(cipher->salt, 8);
    printf("ssl.cipher.key: %s\n", ssl.cipher.key);
    printf("ssl.cipher.password: %s\n", ssl.cipher.password);
    printf("ssl.cipher.salt: %s\n", ssl.cipher.salt);
    printf("ssl.cipher.vector: %s\n", ssl.cipher.vector);
    
    ssl.cipher.salt = ft_strHexToBin(ssl.cipher.salt, ssl.cipher.saltSz);
    ssl.cipher.saltSz = ft_strlen(ssl.cipher.salt);

    padXbits(&ssl.cipher.salt, ssl.cipher.saltSz, KEY_byteSz);
    ssl.cipher.saltSz = KEY_byteSz;
    // printf("salt key: \n");
    printBits(ssl.cipher.salt, KEY_byteSz);
    exit(0);

    if (cipher->salt)
    {
        padXbits(&cipher->salt, cipher->saltSz, KEY_byteSz);
        cipher->saltSz = KEY_byteSz;
        printBits(cipher->salt, cipher->saltSz);
        
        printf("ssl.cipher.salt: %s\n", ssl.cipher.salt);
    }
}

void    des(t_hash *hash)
{
    init_vars(&ssl.cipher);
    pbkdf2_sha256(ssl.cipher.password, ssl.cipher.salt, 0);
}

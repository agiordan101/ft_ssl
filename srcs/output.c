#include "ft_ssl.h"

// ---------------------- VERBOSE output ---------------------------

void    print_usage_exit()
{
    ft_putstr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");
    ft_putstr("Global flags:\n");
    ft_putstr("\t-help\tDisplay this summary and exit\n");
    ft_putstr("\t-i\tinput file for plaintext\n");
    ft_putstr("\t-o\toutput file for hash\n");
    ft_putstr("\t-q\tquiet mode\n");

    // ft_ssl 1st project
    ft_putstr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstr("Message Digest flags:\n");
    ft_putstr("\t-p\techo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_putstr("\t-r\treverse the format of the output\n");
    ft_putstr("\t-s\tprint the sum of the given string\n");

    // ft_ssl 2nd project
    ft_putstr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstr("Cipher flags:\n");
    ft_putstr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    ft_putstr("\t-d\tdecrypt mode\n");
    ft_putstr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstr("\t-ai\tdecode the input in base64\n");
    ft_putstr("\t-ao\tencode the output in base64\n");
    ft_putstr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstr("\t-k\tsend the key in hex\n");
    ft_putstr("\t-p\tsend password in ascii\n");
    ft_putstr("\t-s\tsend the salt in hex\n");
    ft_putstr("\t-v\tsend initialization vector in hex\n");
    ft_putstr("\t-P\tprint the vector/key and exit\n");
    ft_putstr("\t-nopad\tdisable standard block padding\n");
    // ft_putstr("\t-r: reverse the format of the output\n");

    // ft_ssl 3rd project
    ft_putstr("\nStandard commands:\n\tNot yet...\n");
    freexit(EXIT_SUCCESS);
}

void    file_not_found(t_hash *hash)
{
    ft_putstr("ft_ssl: ");
    ft_putstr(ssl.hash_func);
    ft_putstr(": ");
    ft_putstr(hash->name);
    ft_putstr(": No such file or directory\n");
}

// ---------------------- DATA output ---------------------------

void    hash_64bytesbloc_output(t_hash *p)
{
    Mem_8bits   *hash = p->hash;
    static int  shitret;

    // Print blocs of 64-bytes 
    while (hash < p->hash + p->hashByteSz)
    {
        if ((shitret = write(
                ssl.fd_out,
                hash,
                hash + 64 < p->hash + p->hashByteSz ? 64 : p->hash + p->hashByteSz - hash
            )) < 0)
            write_failed("write() failed in hash_8bits_output() function (64-bits bloc part).\n");
        ft_putstr("\n");
        hash += 64;
    }
}

void    hash_64bits_output(t_hash *p)
{
    Long_64bits *hash = (Long_64bits *)p->hash;
    // int         bloc64bitsSz = (p->hashByteSz + 7) / 8;
    int         bloc64bitsSz = ((p->hashByteSz + 7) / 8) * 8 / LONG64_ByteSz;

    // printf("Hash (len=%d): %lx\n", bloc64bitsSz, hash[0]);
    for (Long_64bits *tmp = hash; tmp < hash + bloc64bitsSz; tmp += 1)
        ft_printHex(*tmp, LONG64_ByteSz);
    // for (Long_64bits *tmp = hash; tmp < hash + bloc64bitsSz; tmp += 1)
    //     printf("%lx", *tmp);
    // printf("\n");
}

void    hash_32bits_output(t_hash *p)
{
    Word_32bits *hash = (Word_32bits *)p->hash;
    int         bloc32bitsSz = p->hashByteSz / WORD32_ByteSz;
    // int         bloc32bitsSz = (p->hashByteSz + 5) / WORD32_ByteSz; // Beaucoup mieux non ???

    for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
        ft_printHex(*tmp, WORD32_ByteSz);
    // for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
    //     printf("%x", *tmp);
    // printf("\n");
}

void    hash_8bits_output(t_hash *p)
{
    static int shitret;

    // 64-bytes blocs output is only for base64 format without -A flag
    if ((ssl.flags & ao || (ssl.hash_func_addr == base64 && ssl.flags & e)) &&\
        ~ssl.flags & A)
        hash_64bytesbloc_output(p);
    else
    {
        // Find number of padding bytes, to not print them
        int     n_padByte = 0;
        while (p->hash[p->hashByteSz - 1 - n_padByte] <= 0x08)
            n_padByte++;
        // Print one line
        if ((shitret = write(ssl.fd_out, p->hash, p->hashByteSz - n_padByte)) < 0)
            write_failed("write() failed in hash_8bits_output() function (plain part).\n");
        // ft_putstr("\n");
    }
}

void    hash_output(t_hash *hash, int hashBlocByteSz)
{
    if (hashBlocByteSz == MEM8_ByteSz || ssl.flags & ao) //base64 command  OR  des flag d  OR  a | ao flags (base64 output format)
        hash_8bits_output(hash);
    else if (hashBlocByteSz == WORD32_ByteSz)
        hash_32bits_output(hash);
    else if (hashBlocByteSz == LONG64_ByteSz)
        hash_64bits_output(hash);
    // printf("\nhashBlocByteSz: %d\n", hashBlocByteSz);
}

void    classic_output(t_hash *hash, int hashBlocByteSz)
{
    ft_putstr(ssl.hash_func);
    ft_putstr(" (");
    ft_putstr(hash->name);
    ft_putstr(") = ");
    hash_output(hash, hashBlocByteSz);
}

// ---------------------- MD output ---------------------------

void    md_stdin_quiet_output(t_hash *hash)
{
    ft_putstr(hash->name);
    ft_putstr("\n");
    hash_output(hash, WORD32_ByteSz);
}

void    md_stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    hash_output(hash, WORD32_ByteSz);
}

void    md_reversed_output(t_hash *hash)
{
    hash_output(hash, WORD32_ByteSz);
    ft_putstr(" ");
    ft_putstr(hash->name);
}

void    md_output(t_hash *hash)
{
    if (hash->stdin)
    {
        if (ssl.flags & q && ssl.flags & p_md)
            md_stdin_quiet_output(hash);
        else if (ssl.flags & q)
            hash_output(hash, WORD32_ByteSz);
        else
            md_stdin_output(hash);
    }
    else if (ssl.flags & q)
        hash_output(hash, WORD32_ByteSz);
    else if (ssl.flags & r)
        md_reversed_output(hash);
    else
        classic_output(hash, WORD32_ByteSz);
    ft_putstr("\n");
}

// ---------------------- CIPHER output ---------------------------

void    cipher_output(t_hash *hash)
{
    int hashBlocByteSz = MEM8_ByteSz;

    // if (ssl.hash_func_addr == des)
    // {
    //     if (ssl.flags & d)
    //         hashBlocByteSz = MEM8_ByteSz;
    //     else
    //         hashBlocByteSz = LONG64_ByteSz;
    // }
    // else
    //     hashBlocByteSz = MEM8_ByteSz;

    // if (ssl.hash_func_addr == base64)
    // {
    //     // WTFFF ???? stop do that
        // if (((char *)hash->hash)[hash->hashByteSz / 4 - 1] == '\n')
        //     ((char *)hash->hash)[hash->hashByteSz / 4 - 1] = '\0'; //To remove \n, it's like 'echo -n <node->msg> | ./ft_ssl ...'
    // }
    if (ssl.flags & (o | q))
        hash_output(hash, hashBlocByteSz);
    else
        classic_output(hash, hashBlocByteSz);
}

// ---------------------- GLOBAL output ---------------------------

void    output(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash);
    else if (ssl.command & MD)
        md_output(hash);
    else if (ssl.command & CIPHER)
        cipher_output(hash);
    else
        ft_putstdout("This command doesn't handle an output.");
}

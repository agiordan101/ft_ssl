#include "ft_ssl.h"

// ---------------------- VERBOSE output ---------------------------

void    print_usage_exit()
{
    ft_putstderr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");
    ft_putstderr("Global flags:\n");
    ft_putstderr("\t-help\tDisplay this summary and exit\n");
    ft_putstderr("\t-p\tforce data reception in stdin\n");
    ft_putstderr("\t-s\tinput data as string\n");
    ft_putstderr("\t-i\tinput data as file\n");
    ft_putstderr("\t-o\toutput file\n");
    ft_putstderr("\t-q\tquiet mode\n");

    // ft_ssl 1st project
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("Message Digest flags:\n");
    ft_putstderr("\t-r\treverse the format of the output\n");

    // ft_ssl 2nd project
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstderr("Cipher flags:\n");
    ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    ft_putstderr("\t-d\tdecrypt mode\n");
    ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    ft_putstderr("\t-ai\tdecode the input in base64\n");
    ft_putstderr("\t-ao\tencode the output in base64\n");
    ft_putstderr("\t-A\tUsed with -[a | ai | ao] to specify base64 buffer as a single line\n");
    ft_putstderr("\t-k\tsend the key in hex\n");
    ft_putstderr("\t-p\tsend password in ascii\t(Override the behavior of global flag -p)\n");
    ft_putstderr("\t-s\tsend the salt in hex\t(Override the behavior of global flag -s)\n");
    ft_putstderr("\t-v\tsend initialization vector in hex\n");
    ft_putstderr("\t-P\tprint the vector/key and exit\n");
    ft_putstderr("\t-nopad\tdisable standard block padding\n");
    ft_putstderr("\t-iter\tSpecify the iteration count of PBKDF2\n");

    // ft_ssl 3rd project
    ft_putstderr("\nStandard commands:\n\tisprime\n");
    ft_putstderr("isprime command flags:\n");
    ft_putstderr("\t-prob\tprobability requested for Miller-Rabin primality test of the given number in percentile (0 < p < 100)\n");
    ft_putstderr("Standard flags:\n");

    freexit(EXIT_SUCCESS);
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
            write_failed("write() failed in hash_8bits_output() function (64-bits bloc part).\n", ssl.fd_out);
        ft_putstrfd(ssl.fd_out, "\n");
        hash += 64;
    }
}

void    hash_32bits_output(t_hash *p)
{
    Word_32bits *hash = (Word_32bits *)p->hash;
    int         bloc32bitsSz = p->hashByteSz / WORD32_byteSz;

    for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
        ft_printHex(*tmp, WORD32_byteSz);
    // for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
    //     printf("%x", *tmp);
    // printMemHex(p->hash, p->hashByteSz, "out");
}

void    hash_8bits_output(t_hash *p)
{
    static int shitret;

    // 64-bytes blocs output is only for base64 format without -A flag
    if (~ssl.flags & A &&\
        (ssl.flags & ao || (ssl.command_addr == base64 && ssl.flags & e)))
        hash_64bytesbloc_output(p);
    else
    {
        // Find number of padding bytes, to not print them
        int     n_padByte = 0;
        while (p->hash[p->hashByteSz - 1 - n_padByte] <= 0x08)
            n_padByte++;
        // Print one line
        if ((shitret = write(ssl.fd_out, p->hash, p->hashByteSz - n_padByte)) < 0)
            write_failed("write() failed in hash_8bits_output() function (plain part).\n", ssl.fd_out);
    }
}

void    hash_output(t_hash *hash)
{
    if (ssl.command_familly != MD || ssl.flags & ao) //base64 command_familly  OR  des flag d  OR  a | ao flags (base64 output format)
        hash_8bits_output(hash);
    else
        hash_32bits_output(hash);
    // Since isprime was added
    // if (ssl.command_familly == CIPHER || ssl.flags & ao) //base64 command_familly  OR  des flag d  OR  a | ao flags (base64 output format)
    //     hash_8bits_output(hash);
    // else if (ssl.command_familly == MD)
    //     hash_32bits_output(hash);
}

void    classic_output(t_hash *hash)
{
    ft_putstr(ssl.command_title);
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    hash_output(hash);
}

void    stdin_output(t_hash *hash)
{
    ft_putstr("(");
    ft_putstr(hash->name);
    ft_putstr(")= ");
    hash_output(hash);
}

void    stdin_quiet_output(t_hash *hash)
{
    ft_putstr(hash->name);
    ft_putstr("\n");
    hash_output(hash);
}

void    reversed_output(t_hash *hash)
{
    hash_output(hash);
    ft_putstr(" ");
    ft_putstr(hash->name);
}

void    output_based_on_flags(t_hash *hash)
{
    if (ssl.flags & q && ssl.flags & p && hash->stdin)
        stdin_quiet_output(hash);
    else if (ssl.flags & q)
        hash_output(hash);
    else if (hash->stdin && ssl.command_familly == MD)
        stdin_output(hash);
    else if (ssl.flags & r)
        reversed_output(hash);
    else
        classic_output(hash);

    if (ssl.command_familly == MD)          // Very bad code
        ft_putstrfd(ssl.fd_out, "\n");
}

// ---------------------- GLOBAL output ---------------------------

void    output(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash->name);
    else
        output_based_on_flags(hash);
}
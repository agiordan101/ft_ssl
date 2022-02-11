#include "ft_ssl.h"

// ---------------------- HASH commands output ---------------------------

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
        ft_putstr("\n");
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

    // Find number of padding bytes, to not print them
    int     n_padByte = 0;
    while (p->hash[p->hashByteSz - 1 - n_padByte] <= 0x08)
        n_padByte++;
    // Print one line
    if ((shitret = write(ssl.fd_out, p->hash, p->hashByteSz - n_padByte)) < 0)
        write_failed("write() failed in hash_8bits_output() function (plain part).\n", ssl.fd_out);
}

void    hash_output(t_hash *hash)
{
    //base64 command_familly  OR  des flag d  OR  a | ao flags (base64 output format)
    // if (ssl.command.command & ~MD || ssl.flags & ao)

    // 64-bytes blocs output is only for base64 format without -A flag
    // if 
    if (~ssl.flags & A &&\
        ((ssl.enc_o_cmd.command & BASE64) || (ssl.enc_o_cmd.command == 0 && ssl.command.command & BASE64)))
        hash_64bytesbloc_output(hash);
    else if (ssl.enc_o_cmd.command & MD || (ssl.enc_o_cmd.command == 0 && ssl.command.command & MD))
        hash_32bits_output(hash);
    else
        hash_8bits_output(hash);
}


// ---------------------- Commands output ---------------------------

void    genprime_output(t_hash *hash)
{
    ft_putstr(ssl.command.command_title);
    hash_output(hash);
    // ft_putstr(hash->hash);
}

void    genrsa_output(t_hash *hash)
{
    ft_putstr(ssl.command.command_title);
    
    hash_output(hash);
    // ft_putstr(hash->hash);
}

// ---------------------- Outputs based on flags ---------------------------

void    classic_output(t_hash *hash)
{
    ft_putstr(ssl.command.command_title);
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

void    output_hash_based_on_flags(t_hash *hash)
{
    if (ssl.flags & q && ssl.flags & p && hash->stdin)
        stdin_quiet_output(hash);
    else if (ssl.flags & q)
        hash_output(hash);
    else if (hash->stdin && ssl.command.command & MD)
        stdin_output(hash);
    else if (ssl.flags & r)
        reversed_output(hash);
    else if (ssl.command.command & GENPRIME)
        genprime_output(hash);
    else if (ssl.command.command & GENRSA)
        genrsa_output(hash);
    else
        classic_output(hash);
}

// ---------------------- GLOBAL output ---------------------------

void    output(t_hash *hash)
{
    if (hash->error == FILENOTFOUND)
        file_not_found(hash->name);
    // else if (ssl.command.command & THASHNEED_COMMANDS)
    else
        output_hash_based_on_flags(hash);

    // Always display '\n'. Except the last one if -q flag is up)
    if (hash->next || ~ssl.flags & q)
        ft_putstr("\n");
}

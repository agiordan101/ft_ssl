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
        hash += 64;
        if (hash < p->hash + p->hashByteSz)
            ft_putstr("\n");
    }
}

void    hash_32bits_output(t_hash *p)
{
    Word_32bits *hash = (Word_32bits *)p->hash;
    int         bloc32bitsSz = p->hashByteSz / WORD32_byteSz;

    for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
        _ft_printHex(*tmp, WORD32_byteSz, HEXABASE_low, 1);
    
    // for (Word_32bits *tmp = hash; tmp < hash + bloc32bitsSz; tmp += 1)
    //     printf("%x", *tmp);
    // printMemHex(p->hash, p->hashByteSz, "out");
}

void    hash_8bits_output(t_hash *p)
{
    static int shitret;

    // Print one line
    if ((shitret = write(ssl.fd_out, p->hash, p->hashByteSz)) < 0)
        write_failed("write() failed in hash_8bits_output() function (plain part).\n", ssl.fd_out);
}

void    hash_output(t_hash *hash)
{
    // 64-bytes blocs output is only for base64 format without -A flag
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
}

void    rsa_output(t_hash *hash)
{
    // if (ssl.command.command & RSAUTL)
    //     hash_output(hash);
    // else if (~ssl.flags & noout)
    if (~ssl.flags & noout)
    {
        ft_putstderr("writing RSA key\n");
        if (((t_rsa *)ssl.command.command_data)->outform == PEM)
        {   // PEM form construction
            ft_putstr(ssl.flags & pubout ? RSA_PUBLIC_KEY_HEADER : RSA_PRIVATE_KEY_HEADER);
            ft_putstr("\n");
            hash_output(hash);
            ft_putstr("\n");
            ft_putstr(ssl.flags & pubout ? RSA_PUBLIC_KEY_FOOTER : RSA_PRIVATE_KEY_FOOTER);
            ft_putstr("\n");
        }
        else
            hash_output(hash);
    }
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
    else if (ssl.flags & q) // Before commands output
        hash_output(hash);
    else if (ssl.command.command & GENPRIME)
        genprime_output(hash);
    else if (ssl.command.command & (GENRSA + RSA))
        rsa_output(hash);
    else if (hash->stdin && ssl.command.command & MD)
        stdin_output(hash);
    else if (ssl.flags & r)
        reversed_output(hash);
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
    if (hash->next || (ssl.command.command & ~STANDARDS && ~ssl.flags & q))
        ft_putstr("\n");
}

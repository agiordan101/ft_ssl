#include "ft_ssl.h"

static void     print_flag_usage(e_flags flag)
{
    if (flag & help)
        ft_putstderr("\t-help\tDisplay this summary and exit\n");
    else if (flag & i_)
        ft_putstderr("\t-i\tinput data as file\n");
    else if (flag & o)
        ft_putstderr("\t-o\toutput file\n");
    else if (flag & a)
        ft_putstderr("\t-a\tdecode/encode the input/output in base64, depending on the encrypt mode\n");
    // else if (flag & ai)
    //     ft_putstderr("\t-ai\tdecode the input in base64\n");
    // else if (flag & ao)
    //     ft_putstderr("\t-ao\tencode the output in base64\n");
    else if (flag & A)
        ft_putstderr("\t-A\tUsed with -[a | -deci base64 | -enco base64] to specify base64 buffer as a single line\n");
    else if (flag & q)
        ft_putstderr("\t-q\tquiet mode\n");
    else if (flag & r)
        ft_putstderr("\t-r\treverse the format of the output\n");
    else if (flag & deci)
        ft_putstderr("\t-deci\tdecode the input with the given hashing command (command flags can be passed)\n");
    else if (flag & enco)
        ft_putstderr("\t-enco\tencode the output with the given hashing command (command flags can be passed)\n");
    else if (flag & s)
        ft_putstderr("\t-s\tinput data as string\n");
    else if (flag & p)
        ft_putstderr("\t-p\tforce data reception in stdin\n");
    else if (flag & e)
        ft_putstderr("\t-e\tencrypt mode (default mode) (-e has priority over -d)\n");
    else if (flag & d)
        ft_putstderr("\t-d\tdecrypt mode\n");
    // else if (flag & ecb)
    //     ft_putstderr("\t-ecb\tECB mode of DES (Electronic Code Book)\n");
    // else if (flag & cbc)
    //     ft_putstderr("\t-cbc\tCBC mode of DES (Cipher Block Chaining)\n");
    else if (flag & k_des)
        ft_putstderr("\t-k\tsend the key in hex\n");
    else if (flag & p_des)
        ft_putstderr("\t-p\tsend password in ascii\t(Override the behavior of global flag -p)\n");
    else if (flag & s_des)
        ft_putstderr("\t-s\tsend the salt in hex\t(Override the behavior of global flag -s)\n");
    else if (flag & v_des)
        ft_putstderr("\t-v\tsend initialization vector in hex\n");
    else if (flag & P_des)
        ft_putstderr("\t-P\tprint the vector/key and exit\n");
    else if (flag & nopad)
        ft_putstderr("\t-nopad\tdisable standard block padding\n");
    else if (flag & pbkdf2_iter)
        ft_putstderr("\t-iter\tSpecify the iteration count of PBKDF2\n");
    else if (flag & prob)
        ft_putstderr("\t-prob\tprobability requested for Miller-Rabin primality test in percentile (0 < p <= 100)\n");
    else
    {
        printf("WTFF ?\n");
        exit(0);
    }
}

static void     print_command_flags(e_flags flags)
{
    for (int i = 0, flag = 1; i < N_FLAGS; i++, flag <<= 1)
        if (flag & flags)
            print_flag_usage(flag);
}

static void     print_md_usage()
{
    ft_putstderr("Usage: ./ft_ssl md5 | sha256 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(MD_flags);
}

static void     print_base64_usage()
{
    ft_putstderr("Usage: ./ft_ssl base64 [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(BASE64_flags);
}

static void     print_des_usage()
{
    ft_putstderr("Usage: ./ft_ssl des | des-ecb | des-cbc [files] [flags]\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(DES_flags);
}

static void     print_genprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl genprime [files] [flags]\n");
    ft_putstderr("Generate big 64-bits random prime number.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENPRIME_flags);
}

static void     print_isprime_usage()
{
    ft_putstderr("Usage: ./ft_ssl isprime [files] [flags]\n");
    ft_putstderr("Handle 64-bits numbers (up to ~19 digits).\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(ISPRIME_flags);
}

static void     print_genrsa_usage()
{
    ft_putstderr("Usage: ./ft_ssl genrsa [files] [flags]\n");
    ft_putstderr("Generating RSA private key, 64-bits long modulus.\n\n");
    ft_putstderr("Valid flags are:\n");
    print_command_flags(GENRSA_flags);
}

void    print_command_usage(e_command cmd)
{
    if (cmd & MD)
        print_md_usage();
    else if (cmd & BASE64)
        print_base64_usage();
    else if (cmd & DES)
        print_des_usage();
    else if (cmd & GENPRIME)
        print_genprime_usage();
    else if (cmd & ISPRIME)
        print_isprime_usage();
    else if (cmd & GENRSA)
        print_genrsa_usage();
    freexit(EXIT_SUCCESS);
}

void    print_commands()
{
    ft_putstderr("usage: ./ft_ssl <command> [files] [flags]\n");
    ft_putstderr("see './ft_ssl <command> -help' for command details.\n");
    ft_putstderr("\nMessage Digest commands:\n\tmd5\n\tsha256\n");
    ft_putstderr("\nCipher commands:\n\tbase64\n\tdes\t(Default as des-cbc)\n\tdes-ecb\n\tdes-cbc\n");
    ft_putstderr("\nPrime numbers commands:\n\tgenprime\n\tisprime\n");
    ft_putstderr("\nStandard commands:\n\tgenrsa\n");
    freexit(EXIT_SUCCESS);
}

void    print_global_usage()
{
    ft_putstderr("Type './ft_ssl help' for commands list.\n");
    freexit(EXIT_SUCCESS);
}

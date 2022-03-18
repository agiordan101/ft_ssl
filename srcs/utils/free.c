#include "ft_ssl.h"

static void     t_rsa_free(t_rsa *rsa)
{

    // if (rsa->keyfile_data)
    //     free(rsa->keyfile_data);
    // if (rsa->der_content)
    //     free(rsa->der_content);

    int n_max_bigints = RSA_PRIVATE_KEY_INTEGERS_COUNT + RSA_PUBLIC_KEY_INTEGERS_COUNT;
    Mem_8bits   *bigints[RSA_PRIVATE_KEY_INTEGERS_COUNT + RSA_PUBLIC_KEY_INTEGERS_COUNT] = {
        rsa->pubkey_bigint.modulus, rsa->pubkey_bigint.enc_exp,
        rsa->privkey_bigint.version, rsa->privkey_bigint.modulus,
        rsa->privkey_bigint.enc_exp, rsa->privkey_bigint.dec_exp,
        rsa->privkey_bigint.p, rsa->privkey_bigint.q,
        rsa->privkey_bigint.crt_dmp1, rsa->privkey_bigint.crt_dmq1, rsa->privkey_bigint.crt_iqmp
    };
    for (int i = 0; i < n_max_bigints; i++)
        if (bigints[i])
            free(bigints[i]);
}

static void    t_command_free(t_command *cmd)
{
    if (cmd->command_data)
    {
        if (cmd->command & DES && ((t_des *)cmd->command_data)->password)
            free(((t_des *)cmd->command_data)->password);
        if (cmd->command & RSA_CMDS)
            t_rsa_free((t_rsa *)cmd->command_data);
        free(cmd->command_data);
    }
}

void        ssl_free()
{
    t_command_free(&ssl.dec_i_cmd);
    t_command_free(&ssl.command);
    t_command_free(&ssl.enc_o_cmd);

    t_hash_list_free(ssl.hash);

    free(ssl.ulrandom_path);
    if (ssl.ulrandom_fd > 0)
        close(ssl.ulrandom_fd);

    if (ssl.flags & o)
        close(ssl.fd_out);
}

void          freexit(int exit_state)
{
    ssl_free();
    exit(exit_state);
}
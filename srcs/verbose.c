#include "ft_ssl.h"

void    print_usage()
{
    ft_putstr("usage: ft_ssl <algorithm> [flags] [file | string]\n\n");
    ft_putstr("Algorithms:\n\tmd5\n\tsha256\n\n");
    ft_putstr("Flags:\n");
    ft_putstr("\t-p: echo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_putstr("\t-q: quiet mode\n");
    ft_putstr("\t-r: reverse the format of the output\n");
    ft_putstr("\t-s: print the sum of the given string\n");
}

echo "For each command line, this script will display duplicate things or nothing if there is no error"
echo "ft_ssl encrypt / openssl decrypt ->"
echo "1:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q | openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -out unitests_out -d && diff $1 unitests_out
echo "2:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a | openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -out unitests_out -a -d && diff $1 unitests_out
echo "3:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a -A | openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -out unitests_out -a -d -A && diff $1 unitests_out

echo "\nopenssl encrypt / ft_ssl decrypt ->"
echo "4:"
openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -in $1 | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -d -o unitests_out && diff $1 unitests_out
echo "5:"
openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -in $1 -a | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -a -d -o unitests_out && diff $1 unitests_out
echo "6:"
openssl des-cbc -K 0123456789abcdef -iv fedcba4242abcdef -in $1 -a -A | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -a -A -d -o unitests_out && diff $1 unitests_out

echo "\nft_ssl encrypt / ft_ssl decrypt ->"
echo "7:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -o unitests_out -d && diff $1 unitests_out
echo "8:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -o unitests_out -a -d && diff $1 unitests_out
echo "9:"
./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a -A | ./ft_ssl des-cbc -k 0123456789abcdef -v fedcba4242abcdef -o unitests_out -a -A -d && diff $1 unitests_out
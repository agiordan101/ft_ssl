make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests des-cbc: For each command line, this script will display duplicate things or nothing if there is no error"
echo "\nft_ssl encrypt / openssl decrypt ->"
echo "1:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q | openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -out unitests_out -d && diff $1 unitests_out
echo "2:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q -a | openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -out unitests_out -a -d && diff $1 unitests_out
echo "3:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q -a -A | openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -out unitests_out -a -d -A && diff $1 unitests_out

echo "\nopenssl encrypt / ft_ssl decrypt ->"
echo "4:"
openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -in $1 | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -d -o unitests_out -q && diff $1 unitests_out
echo "5:"
openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -in $1 -a | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -a -d -o unitests_out -q && diff $1 unitests_out
echo "6:"
openssl des-cbc -K 2f6e87379383458c -iv fedcba4242abcdef -in $1 -a -A | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -a -A -d -o unitests_out -q && diff $1 unitests_out

echo "\nft_ssl encrypt / ft_ssl decrypt ->"
echo "7:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -o unitests_out -q -d && diff $1 unitests_out
echo "8:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q -a | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -o unitests_out -q -a -d && diff $1 unitests_out
echo "9:"
./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -i $1 -q -a -A | ./ft_ssl des-cbc -k 2f6e87379383458c -v fedcba4242abcdef -o unitests_out -q -a -A -d && diff $1 unitests_out

rm unitests_out
make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests des-ecb: For each command line, this script will display duplicate things or nothing if there is no error"
echo "\nft_ssl encrypt / openssl decrypt ->"
echo "1:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q | openssl des-ecb -K 0123456789abcdef -out ft_ssl_out -d && diff $1 ft_ssl_out
echo "2:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q -a | openssl des-ecb -K 0123456789abcdef -out ft_ssl_out -a -d && diff $1 ft_ssl_out
echo "3:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q -a -A | openssl des-ecb -K 0123456789abcdef -out ft_ssl_out -a -d -A && diff $1 ft_ssl_out

echo "\nopenssl encrypt / ft_ssl decrypt ->"
echo "4:"
openssl des-ecb -K 0123456789abcdef -in $1 | ./ft_ssl des-ecb -k 0123456789abcdef -d -o ft_ssl_out -q && diff $1 ft_ssl_out
echo "5:"
openssl des-ecb -K 0123456789abcdef -in $1 -a | ./ft_ssl des-ecb -k 0123456789abcdef -a -d -o ft_ssl_out -q && diff $1 ft_ssl_out
echo "6:"
openssl des-ecb -K 0123456789abcdef -in $1 -a -A | ./ft_ssl des-ecb -k 0123456789abcdef -a -A -d -o ft_ssl_out -q && diff $1 ft_ssl_out

echo "\nft_ssl encrypt / ft_ssl decrypt ->"
echo "7:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q | ./ft_ssl des-ecb -k 0123456789abcdef -o ft_ssl_out -q -d && diff $1 ft_ssl_out
echo "8:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q -a | ./ft_ssl des-ecb -k 0123456789abcdef -o ft_ssl_out -q -a -d && diff $1 ft_ssl_out
echo "9:"
./ft_ssl des-ecb -k 0123456789abcdef -i $1 -q -a -A | ./ft_ssl des-ecb -k 0123456789abcdef -o ft_ssl_out -q -a -A -d && diff $1 ft_ssl_out

rm ft_ssl_out
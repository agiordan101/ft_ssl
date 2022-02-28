make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests des-cbc with pbkdf2: Each command line should behave like test 0 (duplicate output is correct too)"
echo "\nopenssl encrypt / openssl decrypt ->"
echo "Test 0:"
openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -in $1 | openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -out ft_ssl_out -d && diff $1 ft_ssl_out

echo "\nft_ssl encrypt / openssl decrypt ->"
echo "Test 1:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q | openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -out ft_ssl_out -d && diff $1 ft_ssl_out
echo "Test 2:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a | openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -out ft_ssl_out -a -d && diff $1 ft_ssl_out
echo "Test 3:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a -A | openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -out ft_ssl_out -a -d -A && diff $1 ft_ssl_out

echo "\nopenssl encrypt / ft_ssl decrypt ->"
echo "Test 4:"
openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -in $1 | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -d -o ft_ssl_out -q && diff $1 ft_ssl_out
echo "Test 5:"
openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -in $1 -a | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -a -d -o ft_ssl_out -q && diff $1 ft_ssl_out
echo "Test 6:"
openssl des-cbc -iter 420 -S a1b2c3d4e5f6 -pbkdf2 -pass "pass:0123456789abcdef" -iv fedcba4242abcdef -in $1 -a -A | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -a -A -d -o ft_ssl_out -q && diff $1 ft_ssl_out

echo "\nft_ssl encrypt / ft_ssl decrypt ->"
echo "Test 7:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -o ft_ssl_out -q -d && diff $1 ft_ssl_out
echo "Test 8:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -o ft_ssl_out -q -a -d && diff $1 ft_ssl_out
echo "Test 9:"
./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -i $1 -q -a -A | ./ft_ssl des-cbc -iter 420 -s a1b2c3d4e5f6 -p 0123456789abcdef -v fedcba4242abcdef -o ft_ssl_out -q -a -A -d && diff $1 ft_ssl_out

rm ft_ssl_out
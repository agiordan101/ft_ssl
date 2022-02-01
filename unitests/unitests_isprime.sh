make -C .. > /dev/null
cp ../ft_ssl . > /dev/null

echo "\n --- Unitests isprime: This script will display differences if a potential error is found"

echo "False
False
False
False
True
True
True
True" > prime_response

./ft_ssl isprime -q -s "42 is nice" -s "0" -s "1" -s "3875632603423" -s "99675679351" -s "6997511168079562241" -s "8939609202503911157" -s "6600182936853012259" > ft_ssl_response

diff ft_ssl_response prime_response
rm ft_ssl_response prime_response ft_ssl > /dev/null

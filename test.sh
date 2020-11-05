echo "#################################"
echo "Good adresses"
echo "#################################"
dig @127.0.0.1 -p 3333 google.com
dig @127.0.0.1 -p 3333 www.seznam.com
dig @127.0.0.1 -p 3333 www.seznam.cz

echo "#################################"
echo "Filtered adresses"
echo "#################################"
dig @127.0.0.1 -p 3333 24log.com
dig @127.0.0.1 -p 3333 thebugs.ws
dig @127.0.0.1 -p 3333 lol.thebugs.ws
dig @localhost -p 3333 wow.com
dig @localhost -p 3333 asda.wow.com

echo "#################################"
echo "Not implemented"
echo "#################################"
dig @127.0.0.1 -p 3333 -x 216.58.220.110
dig @127.0.0.1 -p 3333 mx fit.vutbr.cz

echo "#################################"
echo "Not existing adresses"
echo "#################################"
dig @127.0.0.1 -p 3333 gooasdasdagle.com
dig @127.0.0.1 -p 3333 www.seznam.cz/adsa

# ./dns -p 3333 -f bad_domain_name_long -s 8.8.8.8 			autorativní server
# ./dns -p 3333 -f bad_domain_name_long -s 127.0.0.53			neautorativní server
# ./dns -p 3333 -f bad_domain_name_long - -s 2001:4860:4860::8844		ipv6 server
# valgrind --leak-check=full ./dns -p 3333 -f test_soubor -s 8.8.8.8

# refused query
# dig @ns1.google.com yahoo.com

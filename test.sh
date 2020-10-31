echo "#################################"
echo "Good adress"
echo "#################################"
dig @127.0.0.1 -p 3333 google.com
dig @127.0.0.1 -p 3333 www.seznam.com
dig @127.0.0.1 -p 3333 www.seznam.cz

echo "#################################"
echo "Filtered adress"
echo "#################################"
dig @127.0.0.1 -p 3333 24log.com
dig @127.0.0.1 -p 3333 thebugs.ws	

echo "#################################"
echo "Not implemented"
echo "#################################"
dig @127.0.0.1 -p 3333 -x 216.58.220.110
dig @127.0.0.1 -p 3333 mx fit.vutbr.cz

echo "#################################"
echo "not existing adress"
echo "#################################"
dig @127.0.0.1 -p 3333 gooasdasdagle.com
dig @127.0.0.1 -p 3333 www.seznam.cz/adsa

# sudo ./dns -p 3333 -f bad_domain_name_long -s 8.8.8.8 			autorativní server
# sudo ./dns -p 3333 -f bad_domain_name_long -s 127.0.0.53			neautorativní server
# sudo ./dns -p 3333 -f bad_domain_name_long - -s 2001:4860:4860::8844		ipv6 server
# sudo valgrind --leak-check=full ./dns -p 3333 -f test_soubor -s 8.8.8.8

# refused query
# dig @ns1.google.com yahoo.com



echo "#################################"
echo "Good adresses -- NOERROR"
echo "#################################"
dig @127.0.0.1 -p 33333 google.com
dig @127.0.0.1 -p 33333 www.seznam.com
dig @127.0.0.1 -p 33333 www.seznam.cz
dig @localhost -p 33333 stackoverflow.com

echo "#################################"
echo "Filtered adresses -- REFUSED"
echo "#################################"
dig @127.0.0.1 -p 33333 24log.com
dig @127.0.0.1 -p 33333 thebugs.ws
dig @127.0.0.1 -p 33333 lol.thebugs.ws
dig @localhost -p 33333 wow.com
dig @localhost -p 33333 asda.wow.com
dig @localhost -p 33333 as.ncie.wow.com

echo "#################################"
echo "Not implemented -- NOTIMP"
echo "#################################"
dig @127.0.0.1 -p 33333 -x 216.58.220.110
dig @127.0.0.1 -p 33333 mx fit.vutbr.cz

echo "#################################"
echo "Not existing adresses -- NXDOMAIN"
echo "#################################"
dig @127.0.0.1 -p 33333 gooasdasdagle.com
dig @127.0.0.1 -p 33333 www.seznam.cz/adsa

# ./dns -p 33333 -f bad_domain_name -s 8.8.8.8 			        ipv4 autorativní    server
# ./dns -p 33333 -f bad_domain_name -s 127.0.0.53			    ipv4 neautorativní  server
# ./dns -p 33333 -f bad_domain_name -s 2001:4860:4860::8844		ipv6 autorativni    server
# valgrind --leak-check=full ./dns -p 33333 -f test_soubor -s 8.8.8.8

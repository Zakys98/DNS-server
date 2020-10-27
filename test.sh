dig @127.0.0.1 -p 3333 google.com
dig google.com
dig @127.0.0.53 google.com

echo "#################################"
echo "Filtered adress"
echo "#################################"
dig @127.0.0.1 -p 3333 24log.com	

echo "#################################"
echo "Not implemented"
echo "#################################"
dig @127.0.0.1 -p 3333 -x 216.58.220.110 #repair 
dig +noedns @127.0.0.1 -p 3333 -x 216.58.220.110

echo "#################################"
echo "not existing adress"
echo "#################################"
dig @127.0.0.1 -p 3333 gooasdasdagle.com
dig gooasdasdagle.com

# jde o to jesltli posílám na autorativní dns resolver nebo ne
# sudo ./dns -p 3333 -f test_soubor -s 8.8.8.8
# sudo ./dns -p 3333 -f test_soubor -s 127.0.0.53
# sudo valgrind --leak-check=full ./dns -p 3333 -f test_soubor -s 8.8.8.8







#!/bin/bash

echo "Test ID 1."
actualSHA512="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
mySHA512="$(./project -f tests/test1.txt)"
echo "Actual SHA-512: " $actualSHA512
echo "My SHA-512:     " $mySHA512
if [[ $mySHA512 == $actualSHA512 ]];
then
    echo "Match."
else
    echo "Fail."
fi

echo -e

echo "Test ID 2."
actualSHA512="9971f8715b30e9f5311403c461aa43cafdb6d7473f2ba2559595cea749acefd1180a447fad604617422614a3891286cd78ef67e1012e39246ce64b8ba9e403d0"
mySHA512="$(./project -f tests/test2.txt)"
echo "Actual SHA-512: " $actualSHA512
echo "My SHA-512:     " $mySHA512
if [[ $mySHA512 == $actualSHA512 ]];
then
    echo "Match."
else
    echo "Fail."
fi

echo -e

echo "Test ID 3."
actualSHA512="8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9"
mySHA512="$(./project -f tests/test3.txt)"
echo "Actual SHA-512: " $actualSHA512
echo "My SHA-512:     " $mySHA512
if [[ $mySHA512 == $actualSHA512 ]];
then
    echo "Match."
else
    echo "Fail."
fi

echo -e

echo "Test ID 4."
actualSHA512="fce89780f28dc8b50c937c93f33af7cf25d8a2e9e9a39bad6a7f3d33834e729a1aeb35039c875cd49bc56b398147fcfda8e30ecb87b8b97387563babee8f03f7"
mySHA512="$(./project -f tests/test4.txt)"
echo "Actual SHA-512: " $actualSHA512
echo "My SHA-512:     " $mySHA512
if [[ $mySHA512 == $actualSHA512 ]];
then
    echo "Match."
else
    echo "Fail."
fi

#!/bin/bash

result () {
    echo "Expected SHA-512: " $expectedSHA512
    echo "Actual SHA-512:   " $actualSHA512

    if [[ $actualSHA512 == $expectedSHA512 ]];
    then
        echo "Pass."
    else
        echo "Fail."
    fi
}

echo -e
echo "Test ID 1."
expectedSHA512="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
actualSHA512="$(./project -f tests/test1.txt)"
result

echo -e
echo "Test ID 2."
expectedSHA512="9971f8715b30e9f5311403c461aa43cafdb6d7473f2ba2559595cea749acefd1180a447fad604617422614a3891286cd78ef67e1012e39246ce64b8ba9e403d0"
actualSHA512="$(./project -f tests/test2.txt)"
result

echo -e
echo "Test ID 3."
expectedSHA512="8ba760cac29cb2b2ce66858ead169174057aa1298ccd581514e6db6dee3285280ee6e3a54c9319071dc8165ff061d77783100d449c937ff1fb4cd1bb516a69b9"
actualSHA512="$(./project -f tests/test3.txt)"
result

echo -e
echo "Test ID 4."
expectedSHA512="4d522ecd479d2984eae9dcd2b53efe151d0aaf9514936a979f3bb6436cd4c981f212a2add40f3659f293ae4cb1ca6b6f7626c2c2c755961c423104e88e2c5562"
actualSHA512="$(./project -f tests/test4.txt)"
result

echo -e
echo "Test ID 5."
expectedSHA512="50b0033e9a9f5d4d145147c8845ef411fdc9c83c724a0088a2afe97f1887bba424dccc0c78417f274c2df3bf223eadb9e4676c0eea539ac4e17e6929ab9843f0"
actualSHA512="$(./project -f tests/test5.txt)"
result

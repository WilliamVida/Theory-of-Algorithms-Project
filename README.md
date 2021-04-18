# Theory of Algorithms Project
Author: William Vida <br>
Lecturer: Ian McLoughlin

## Description
This repository contains my solution to the implementation of the SHA-512 algorithm in C which I was required to produce as part of my final year module Theory of Algorithms. Click on [Project Instructions.md](Project%20Instructions.md) to view the project brief. Click on [NIST.FIPS.180-4.pdf](NIST.FIPS.180-4.pdf) to view the Secure Hash Standard (SHS). This project uses command-line arguments to get the SHA-512 hash value of a given file or text input.

## Compilation
### Prerequisites
GNU Compiler Collection (GCC) must be installed. One can be downloaded [here](https://gcc.gnu.org/).

### Installation
Clone the repository
```sh
git clone https://github.com/WilliamVida/Theory-of-Algorithms-Project
```
### Running the Program
After downloading the repository, enter the directory and in a command line type
```sh
make project
```
To see the help menu, in a command line type
```sh
./project -h
```
To get the SHA-512 hash of a file, in a command line type
```sh
./project -f [name of the file]
```
To get the SHA-512 hash of a piece of text,  in a command line type the text inside single quotes
```sh
./project -t '[text input]'
```

### Running the Tests
To run the tests, in a command line type
```sh
make project
make test
```

## Explanation of the SHA-512 Algorithm
SHA-512 is a hashing algorithm that produces a hash value based on a given data. Hashing algorithms are used in internet security and digital certificates. The SHA-256 algorithm is used by Bitcoin's blockchain for hashing [1]. SHA stands for Secure Hash Algorithm. SHA-512 is part of the SHA-2 hashing function set which was designed by the United States National Security Agency.

Firstly, the SHA-512 algorithm takes in an input. The combined size of the input data must be a multiple of 1024 bits. Bits are added to the input data to get it to the right length. The size of the input should then be 896 bits. The largest number that can be represented as 128 bits is 2¹²⁸-1, which means that message size can match that value at its greatest size [1].

Secondly, SHA-512 uses each block from the output of the previous block to process each block of 1024 bits. SHA-512 then uses the initial hash value $(H^{(0)})$, which contains eight 64-bit words in hexadecimal of the first eight prime numbers(2, 3, 5, 7, 11, 13, 17, 19) [1] [2].

Thirdly, message processing is done by taking one block of 1024 bits at a time from the formatted input. SHA-512 uses constants consisting of eighty constant 64-bit words of the fractional parts of the cube roots of the first eighty prime numbers in hexadecimal. Next is the so-called rounds. Each round takes a word, the output of the previous round and a SHA-512 constant [1] [2].

Finally, the final 128 character length hash value is shown. The SHA-512 hash value of "abc" would be "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f".

## Why Is the SHA-512 Algorithm Important
SHA-512 and SHA-256 are used for password hashing. If an attacker gains access to a database containing passwords, the attacker will only be able to see incomprehensible hash values. However, the attacker might use a dictionary of words and their hash value and hope that one of the hashes match one in the dictionary. Certain parts of the United States government require the use of SHA-2 for the protection of important information. The SHA-512 algorithm is part of the same set of hashing functions as SHA-256, called SHA-2. SHA-2 is implemented in security applications such as Transport Layer Security (TLS), Secure Shell Protocol (SSH) and Internet Protocol Security (IPsec). SHA-256 makes up a very important piece of Bitcoin.  Cryptocurrencies such as Bitcoin use SHA-256 in two main ways, for mining and the creation of Bitcoin addresses [3] [4]. 

## Answers
### Why Can't We Reverse the SHA-512 Algorithm to Retrieve the Original Message from a Hash Digest?
A SHA-512 hash value will take a long time to be reversed as it is a hashing function, not an encryption function. SHA-512 was specifically designed not to be able to be reversed. The only known way to get the original message would be to try every single possible input which would take a long time. There is not even a resemblance of similarity between hash values of similar inputs. This makes hash values of similar input completely alien to each other. For example, changing a letter's case in a word produces a different hash value to the original.

https://crypto.stackexchange.com/questions/45377/why-cant-we-reverse-hashes
https://en.wikipedia.org/wiki/Cryptographic_hash_function

### Can You Design an Algorithm That, Given Enough Time, Will Find Input Messages That Give Each of the Possible 512-Bit Strings?
Assuming the meaning of "enough time" means unlimited time, then, of course, it would be possible. Although the time it takes would depend on the algorithm designed and the speed of the computer. SHA-512 allows almost any input but has a limited number of hash values, 2^512. This number is still extremely large but it means that there is a chance that multiple inputs can output the same hash value.

### How Difficult Is It to Find a Hash Digest Beginning with at Least Twelve Zeros?
SHA-512 has 2^512 possible hash values. As there is no way to specifically get an input whose hash value begins with twelve zeroes, the only way would be to keep trying input combinations until one meets the criteria. The problem with this is that there are too many possible hash values and not enough time with modern computers to find a hash value that meets the criteria. 

https://bitcoin.stackexchange.com/questions/81655/creating-a-hash-that-starts-wtih-9-zeros
https://www.quora.com/What-data-produces-a-SHA256-hash-of-all-zero-bits
https://crypto.stackexchange.com/questions/27782/are-there-any-text-strings-that-will-generate-the-same-sha-512-hash-output
https://stackoverflow.com/questions/16094676/is-it-possible-for-a-sha512-hash-to-start-with-64-zeros
https://crypto.stackexchange.com/questions/64714/why-is-sha-512-limited-to-an-input-of-2128-bits
https://stackoverflow.com/questions/17388177/is-there-a-limit-for-sha256-input

## References
[1] Cryptography: Explaining SHA-512; https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1;

[2] Secure Hash Standard (SHS); National Institute of Standards and Technology;

[3] SHA-2; https://en.wikipedia.org/wiki/SHA-2;

[4] What Is SHA-256 And How Is It Related to Bitcoin?; https://www.mycryptopedia.com/sha-256-related-bitcoin/;

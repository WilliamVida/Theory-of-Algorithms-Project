#include <stdio.h>
#include <inttypes.h>
#include <byteswap.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

// Endianness.
// From https://developer.ibm.com/technologies/systems/articles/au-endianc/.
const int _i = 1;
#define is_little_endian() ((*(char *)&_i) != 0)

// SHA-512 operations.
// Section 2.2.2 of the Secure Hash Standard.
#define ROTL(_x, _n) ((_x << _n) | (_x >> (64 - _n)))
#define ROTR(_x, _n) ((_x >> _n) | (_x << (64 - _n)))
#define SHR(_x, _n) (_x >> _n)

// SHA-512 functions.
// Section 4.1.3 of the Secure Hash Standard.
#define CH(_x, _y, _z) ((_x & _y) ^ (~_x & _z))
#define MAJ(_x, _y, _z) ((_x & _y) ^ (_x & _z) ^ (_y & _z))
#define SIG0(_x) (ROTR(_x, 28) ^ ROTR(_x, 34) ^ ROTR(_x, 39))
#define SIG1(_x) (ROTR(_x, 14) ^ ROTR(_x, 18) ^ ROTR(_x, 41))
#define Sig0(_x) (ROTR(_x, 1) ^ ROTR(_x, 8) ^ SHR(_x, 7))
#define Sig1(_x) (ROTR(_x, 19) ^ ROTR(_x, 61) ^ SHR(_x, 6))

// SHA-512 constants consisting of 80 constant 64-bit words.
// Section 4.2.3 of the Secure Hash Standard.
const uint64_t K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

// SHA-512 initial hash values consisting of eight 64-bit words, in hex.
// Section 5.3.5 of the Secure Hash Standard.
uint64_t H[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179};

// For keeping track of where we are with the input message/padding.
enum Status
{
    READ,
    PAD,
    END
};

union Block
{
    uint8_t bytes[128];
    uint64_t words[16];
    uint64_t sixf[16];
};

int next_block(FILE *f, union Block *M, enum Status *S, uint64_t *nobits)
{
    // Number of bytes read.
    size_t nobytes;

    if (*S == END)
    {
        // Finish.
        return 0;
    }
    else if (*S == READ)
    {
        // Read bytes from the file.
        nobytes = fread(M->bytes, 1, 128, f);

        // Calculate the total bits read so far.
        *nobits = *nobits + (8 * nobytes);

        // Enough room for padding.
        if (nobytes == 128)
        {
            // This happens when we can read 128 bytes from the file.
            // Do nothing.
        }
        else if (nobytes < 120)
        {
            // Append 1 bit.
            M->bytes[nobytes] = 0x80;

            // Append 0 bits.
            for (nobytes++; nobytes < 120; nobytes++)
            {
                M->bytes[nobytes] = 0x00;
            }

            // Append nobits as a big endian integer.
            M->sixf[15] = (is_little_endian() ? bswap_64(*nobits) : *nobits);

            // Change the status to END.
            *S = END;
        }
        else
        {
            // Append 1 bit.
            M->bytes[nobytes] = 0x80;

            // Append 0 bits.
            for (nobytes++; nobytes < 128; nobytes++)
            {
                M->bytes[nobytes] = 0x00;
            }

            // Change the status to PAD.
            *S = PAD;
        }
    }
    else if (*S == PAD)
    {
        // Append 0 bits.
        for (nobytes = 0; nobytes < 120; nobytes++)
        {
            M->bytes[nobytes] = 0x00;
        }

        // Append nobits as a big endian integer.
        M->sixf[15] = (is_little_endian() ? bswap_64(*nobits) : *nobits);

        // Change the status to END.
        *S = END;
    }

    // Swap the byte order of the words if it is little endian.
    if (is_little_endian())
    {
        for (int i = 0; i < 16; i++)
            M->words[i] = bswap_64(M->words[i]);
    }

    return 1;
}

// SHA-512 Hash Computation.
// Section 6.4.2 of the Secure Hash Standard.
int next_hash(union Block *M)
{
    // Message schedule, section 6.4.2.
    uint64_t W[80];

    // Iterator for W.
    int t;

    // Temporary variables.
    uint64_t a, b, c, d, e, f, g, h, T1, T2;

    // Preparing the message schedule.
    // Section 6.4.2, part 1 of the Secure Hash Standard.
    for (t = 0; t <= 15; t++)
        W[t] = M->words[t];

    // Section 6.4.2, part 1 of the Secure Hash Standard.
    for (t = 16; t <= 79; t++)
        W[t] = Sig1(W[t - 2]) + W[t - 7] + Sig0(W[t - 15]) + W[t - 16];

    // Initialise the variables.
    // Section 6.4.2, part 2 of the Secure Hash Standard.
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // Section 6.4.2, part 3 of the Secure Hash Standard.
    for (t = 0; t <= 79; t++)
    {
        T1 = h + SIG1(e) + CH(e, f, g) + K[t] + W[t];
        T2 = SIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Section 6.4.2, part 4 of the Secure Hash Standard.
    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];

    return 0;
}

// Fuction that applies the SHA-512 algorithm on a file outputs the SHA-512 hash value.
void sha512(FILE *f)
{
    // The current block.
    union Block M;

    // Total number of bits read.
    uint64_t nobits = 0;

    // Current status of reading input.
    enum Status S = READ;

    // Loop through the (preprocessed) blocks.
    while (next_block(f, &M, &S, &nobits))
    {
        next_hash(&M);
    }

    for (int i = 0; i < 8; i++)
    {
        printf("%08" PRIx64, H[i]);
    }
    printf("\n");
}

void print_usage()
{
    printf("Usage: ./project -f [file name] | temp -t '[text input]' \n");
    exit(2);
}

// getopt from https://www.youtube.com/watch?v=SjyR74lbZOc&ab_channel=theurbanpenguin.
int main(int argc, char *argv[])
{
    // If the input is not correct.
    if (argc < 2)
    {
        print_usage();
    }

    // File pointer.
    FILE *f;

    // Variables.
    int option;
    int fflag = 0;
    int tflag = 0;

    while ((option = getopt(argc, argv, "t:f:hv")) != -1)
    {
        switch (option)
        {
        // For a file input.
        case 'f':
            if (fflag)
            {
                print_usage();
            }
            else
            {
                fflag++;
                tflag++;
            }

            // Read the file.
            if ((f = fopen(argv[2], "r")) != NULL)
            {
                // Get the hash value.
                sha512(f);

                // Close the file.
                fclose(f);
            }
            else
            {
                printf("Error: The inputted file does not exist.\n");
                return 0;
            }

            break;
        // For a text input.
        case 't':
            if (tflag)
            {
                print_usage();
            }
            else
            {
                fflag++;
                tflag++;
            }

            printf("SHA-512 of an input text.\n");

            // Write the text input to a file and then close it.
            f = fopen("input.txt", "w");
            fprintf(f, argv[2]);
            fclose(f);

            // Open the file.
            f = fopen("input.txt", "r");

            // Get the hash value.
            sha512(f);

            // Close the file.
            fclose(f);

            break;
        // For help.
        case 'h':
            printf("Help.\n");
            printf("To get the SHA-512 of a file, type \"./project -f [file name]\" or to get the SHA-512 of a text input, type \"./project -t '[text input]'\"\n");
            printf("For example, to get the hash value of a file, run \"./project -f input.txt\".\n");
            printf("For example, to get the hash value of a text input, run \"./project -t 'abc'\"\n");
            break;
        default:
            printf("Error.\n");
        }
    }

    return 0;
}

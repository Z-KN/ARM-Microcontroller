#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <time.h>
// #include "rsa.h"
// #include "md5.h"
#include "aes.h"

#include "sys.h"
#include "delay.h"
#include "usart.h"
// char ORIGIN_PLAINTEXT_FILE[20] = "plaintext.txt";
// char ORINGIN_KEY_FILE[20] = "key.txt";

// char SOURCE_PATH[20] = "Alice_Home/";
// char DESTINATION_PATH[20] = "Bob_Home/";

#define PLAINTEXT_NAME        "plaintext.txt"
#define AESKEY_ORIG_NAME      "aeskey_orig.txt"
#define AESKEY_INIT_VECT_NAME "aeskey_init_vect.txt"
#define CIPHERTEXT_NAME       "cipher.txt" // plaintext->ciphertext
#define AESKEY_ENCR_NAME      "aeskey_encr.txt"
#define SIGNATURE_NAME        "signature.txt"
#define ABSTRACT_NAME         "abstract.txt"
#define SOURCE_PATH           "Alice_Home/"
#define DESTINATION_PATH      "Bob_Home/"
#define TEMP_CHAR_LEN 1000
#define MAX_FN_LEN 100 

char plaintext_fn[MAX_FN_LEN]={0};
char signature_fn[MAX_FN_LEN]={0};
char ciphertext_fn_tx[MAX_FN_LEN]={0};
char aeskey_orig_fn[MAX_FN_LEN]={0};
char aeskey_init_vect_tx[MAX_FN_LEN]={0};
char aeskey_init_vect_rx[MAX_FN_LEN]={0};
char aeskey_encr_fn_tx[MAX_FN_LEN]={0};
char aeskey_encr_fn_rx[MAX_FN_LEN]={0};
char ciphertext_fn_rx[MAX_FN_LEN]={0};
char text_decr_fn[MAX_FN_LEN]={0};
char abstract_fn_rx[MAX_FN_LEN]={0};

void hardware_init();
void algorithm_init(); // filename definition, rsa keys, aes initial vector
void plaintext_abstract(char *in_fn, char *out_fn); // use md5
// void plaintext_encrypt(const char *in_fn, const char *out_fn); // use aes
void aeskey_encrypt(char *in_fn, char *out_fn); // use rsa
void transmit(); // tx 3 files, do by copying
void aeskey_decrypt(char *in_fn); // no output file, output is in memory 
// void cipher_decrypt(const char *in_fn, const char *out_fn); // get the decrypted text file in out_fn
void decr_abstract(char *in_fn); // no output file, abstract is in memory
void verify(char *in_fn); // test if equal?


typedef int64_t data_type;
#define MAX_LENGTH 256
#define MAX_NUM_PLAINTEXT 20
#define MAX_NUM_CIPHERTEXT MAX_NUM_PLAINTEXT
#define MAX_B_IN_LINE 1024

// global variable, for debug use in iar


data_type p;
data_type q;
data_type n;
data_type PHIn;
data_type e;
data_type d;
data_type plaintext;
data_type *value_plaintext;
data_type ciphertext[16]={0};  // for encryption
data_type value_cipher[16]={0}; // for decryption
data_type *value_decodedtext;

char str_p[MAX_LENGTH] = {0};
char str_q[MAX_LENGTH] = {0};
char str_n[MAX_LENGTH] = {0};
char str_PHIn[MAX_LENGTH] = {0};
char str_e[MAX_LENGTH] = {0};
char str_d[MAX_LENGTH] = {0};
char *plaintext_set[MAX_NUM_PLAINTEXT]={0};
char ciphertext_set[MAX_NUM_CIPHERTEXT][MAX_LENGTH];
// char plaintext_set[MAX_NUM_PLAINTEXT][MAX_LENGTH]={0}; why error?
char *str_plaintext;
char str_ciphertext[64][64];
//char *str_ciphertext=0;
char str_value_decodedtext[MAX_NUM_PLAINTEXT][MAX_LENGTH]; // store str of value decodedtext
char decodedtext_set[MAX_NUM_PLAINTEXT][MAX_LENGTH];
char decodedtext[MAX_LENGTH];
char *PLAINTEXT_FILE = "plaintext.txt";
char *PRIME_FILE = "primes.txt";
char *DECODEDTEXT_FILE = "decodedtext.txt";
char *CIPHERTEXT_FILE = "ciphertext.txt";
int num_plaintext;
int num_section; // number of section in each converted array
// char de_aeskey[MAX_LENGTH]={0};
char *de_aeskey;


char *myitoa(data_type num, char *str_num, int radix);
void get_primes(data_type *p, data_type *q);
void get_n_PHIn(data_type *n, data_type *PHIn, data_type p, data_type q);
void get_e_d(data_type *e, data_type *d, data_type PHIn);
// data_type get_encode_index(data_type PHIn);
data_type mul_inv(data_type a, data_type b);
data_type squ_mul(data_type x, data_type c, data_type n);
void get_plaintext_set(char *plaintext_set[]);
void get_ciphertext_set(char ciphertext_set[MAX_NUM_CIPHERTEXT][MAX_LENGTH]);
void pre_process(char *plaintext);
char *show_plaintext(char *plaintext);
data_type *divide_and_convert(char *plaintext, int *num_section);
void merge_and_convert(char decodedtext[],char str_value_decodedtext[][MAX_LENGTH]);
void write_decodedtext_set(char decodedtext_set[][MAX_LENGTH]);
void encrypt(char *PLAINTEXT_FILE, char *CIPHERTEXT_FILE);
void decrypt(char *CIPHERTEXT_FILE, char *DECODEDTEXT_FILE);

// To get plaintext from file
void get_plaintext_set(char *plaintext_set[])
{
    FILE *fp;
    if ((fp = fopen(aeskey_orig_fn, "r")) == NULL)
    {
        printf("File open error!\n");
        exit(0);
    }

    int i = 0;
    while (!feof(fp))
    {
        plaintext_set[i] = (char *)malloc(MAX_LENGTH);
        fgets(plaintext_set[i], MAX_B_IN_LINE, fp);
        i++;
    }
    num_plaintext = i - 1; // should -1 if there is an extra blank at the end of the file

    if (fclose(fp))
    {
        printf("File close error!\n");
        exit(0);
    }
}

void get_ciphertext_set(char ciphertext_set[MAX_NUM_CIPHERTEXT][MAX_LENGTH])
{
    FILE *fp;
    if ((fp = fopen(aeskey_encr_fn_rx, "r")) == NULL)
    {
        printf("File open error!\n");
        exit(0);
    }

    int i = 0;
    while (!feof(fp))
    {
        fgets(ciphertext_set[i], MAX_B_IN_LINE, fp);
        ciphertext_set[i][strlen(ciphertext_set[i])-1] = 0;
        //printf("value_cipher[%d]=%s\n",i,ciphertext_set[i]);
        i++;
        // fscanf(fp,"%d",&value_cipher[i++]);

    }


    if (fclose(fp))
    {
        printf("File close error!\n");
        exit(0);
    }
}

// To write the decodedtext to file
void write_decodedtext_set(char decodedtext_set[][MAX_LENGTH])
{
    FILE *fp;
    if ((fp = fopen(DECODEDTEXT_FILE, "w")) == NULL)
    {
        printf("File open error!\n");
        exit(0);
    }
    // for(int i=0;i<num_plaintext;i++)
    //     printf("%s\n",decodedtext_set[i]);
    // here free
    for(int i=0;i<num_plaintext;i++)
        fprintf(fp,"%s\n",decodedtext_set[i]);

    if (fclose(fp))
    {
        printf("File close error!\n");
        exit(0);
    }

}
void pre_process(char *plaintext)
{
    int length;
    length = strlen(plaintext) - 2;
    plaintext[length] = 0;
}

data_type *divide_and_convert(char *plaintext, int *num_section)
{
    int length;
    length = strlen(plaintext);
    *num_section = (length / 4) * 4 < length ? length / 4 + 1 : length / 4;
    data_type *value_plaintext;
    value_plaintext = (data_type *)malloc(sizeof(data_type) * (*num_section));
    for (int i = 0; i < *num_section; i++)
    {
        value_plaintext[i] = 0;
    }
    //for example, I love
    for (int i = 0; i < length; i++)
    {
        char ch = plaintext[i];
        if ('0' <= ch && ch <= '9') // 0-9 convert to '10' - '19'
            ch = ch - '0' + 10;
        else if ('a' <= ch && ch <= 'z') // a-z convert to '20' - '45'
            ch = ch - 'a' + 20;
        else if ('A' <= ch && ch <= 'Z') // A-Z convert to '46' - '71'
            ch = ch - 'A' + 46;
        else if (ch == ' ')
            ch = ch - ' ' + 72;
        else if (ch == '_')
            ch = ch - '_' + 73;

        value_plaintext[i / 4] = value_plaintext[i / 4] * 100 + ch;
    }
    return value_plaintext;
}

void merge_and_convert(char decodedtext[],char str_value_decodedtext[][MAX_LENGTH])
{
    // eg, ["12345678","23456789"]
//   char *decodedtext=(char *)malloc(MAX_LENGTH + 1);
    int i, j;
    for (i = 0; i < MAX_LENGTH + 1; i++)
        decodedtext[i] = 0;
    // char *merged_decodedtext = (char *)calloc(num_section,9*sizeof(char));
    char merged_decodedtext[MAX_LENGTH*2+1] = {0};
    // merged_decodedtext[0]=0;  // initialize 
    // for (i = 0; i < num_section; i++)
    // {
    //     strcat(merged_decodedtext,str_value_decodedtext[i]);
    // }
    for (i = 0; i < 2*MAX_LENGTH + 1; i++)
        merged_decodedtext[i] = 0;    
    // printf("length = %d\n",strlen(merged_decodedtext));
    int k=0;
    for (i = 0; i < num_section; i++)
    {
        for(j=0;j<strlen(str_value_decodedtext[i]);j++)
        {
            merged_decodedtext[k++]=str_value_decodedtext[i][j];
        }
    }

    printf("merged_decodedtext = %s\n",merged_decodedtext);
    //printf("length = %d\n",strlen(merged_decodedtext));
    for (j = 0; j < strlen(merged_decodedtext); j += 2)
    {
        char ch[3];
        ch[0] = merged_decodedtext[j];
        ch[1] = merged_decodedtext[j + 1];
        ch[2]=0;
        int num_ch = atoi(ch);
        //printf("num_ch = %d\n",num_ch);
        if (10 <= num_ch && num_ch <= 19)
            decodedtext[j/2] = num_ch - 10 + '0';
        else if (20 <= num_ch && num_ch <= 45)
            decodedtext[j/2] = num_ch - 20 + 'a';
        else if (46 <= num_ch && num_ch <= 71)
            decodedtext[j/2] = num_ch - 46 + 'A';
        else if (num_ch == 72)
            decodedtext[j/2] = ' ';
        else if (num_ch == 73)
            decodedtext[j/2] = '_';
    }
    decodedtext[j/2]=0;
    //free(merged_decodedtext);
    // return decodedtext;
}

// get two big primes, p, q from am existing prime file randomly
void get_primes(data_type *p, data_type *q)
{
    FILE *fp;
    if ((fp = fopen(PRIME_FILE, "r")) == NULL)
    {
        printf("Prime file open error!\n");
        exit(0);
    }

    data_type num_prime = 0;
    int ch;
    int random_p;
    int random_q;
    while (!feof(fp))
    {
        ch = fgetc(fp);
        if (ch == '\n')
            num_prime++;
    }

    // printf("num_prime=%d\n",num_prime);
    srand((unsigned)time(NULL));
    random_p = (unsigned)1001 * rand() % (num_prime + 1);
    random_q = (unsigned)2001 * rand() % (num_prime + 1);
    // printf("%d\n", random_p);
    // printf("%d\n", random_q);

    char ch_prime[MAX_LENGTH];

    rewind(fp);
    for (int i = 0; i < random_p + 1; i++)
    {
        fgets(ch_prime, sizeof(ch_prime) - 1, fp);
    }
    *p = atol(ch_prime);

    rewind(fp);
    for (int i = 0; i < random_q + 1; i++)
    {
        fgets(ch_prime, sizeof(ch_prime) - 1, fp);
    }
    *q = atol(ch_prime);

    if (fclose(fp))
    {
        printf("File close error!\n");
        exit(0);
    }
}

// get n and PHIn according to determined p and q
void get_n_PHIn(data_type *n, data_type *PHIn, data_type p, data_type q)
{
    *n = p * q;
    *PHIn = (p - 1) * (q - 1);
}

// Judge whether a and b is coprimes
// if return 0, it means a gcd(a,b)!=0
// else it returns the multiplication inverse of b^(-1) mod a
// return d if it exists
data_type mul_inv(data_type a, data_type b)
{
    data_type a0 = a;
    data_type b0 = b;
    data_type t0 = 0;
    data_type t = 1;
    data_type q = a0 / b0;
    data_type r = a0 - q * b0;
    data_type temp;
    while (r > 0)
    {
        temp = (t0 - q * t) % a;
        t0 = t;
        t = temp;
        a0 = b0;
        b0 = r;
        q = a0 / b0;
        r = a0 - q * b0;
    }
    if (b0 != 1)
        // b has no inverse module a
        return 0;
    else if (t < 0)
        t = t + a;
    return t;
}

// calculate x**c mod n
data_type squ_mul(data_type x, data_type c, data_type n)
{
    data_type z = 1;
    int i;
    char charc[MAX_LENGTH + 1] = {0};
    myitoa(c, charc, 2);

    for (i = 0; i <= strlen(charc) - 1; i++)
    {
        z = z * z % n;
        if (charc[i] == '1')
            z = z * x % n;
    }
    return z;
}

void get_e_d(data_type *e, data_type *d, data_type PHIn)
{
    do
    {
        srand((unsigned)time(NULL));
        *e = (unsigned)3001 * rand() % PHIn;
        *d = mul_inv(PHIn, *e);
    } while (*d == 0);
}

char *show_plaintext(char *plaintext)
{
    printf("The AES key is \"%s\"\n", plaintext);
    return plaintext;
}

// To implement the non-standard functino itoa in c library
char *myitoa(data_type num, char *str_num, int radix)
{
    // index chart
    char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint64_t unum;
    int i = 0, j, k;

    if (radix == 10 && num < 0)
    {
        unum = (uint64_t)-num;
        str_num[i++] = '-';
    }
    else
        unum = (uint64_t)num;

    do
    {
        str_num[i++] = index[unum % (unsigned)radix];
        unum /= radix;
    } while (unum);
    str_num[i] = '\0';

    if (str_num[0] == '-')
        k = 1;
    else
        k = 0;

    char temp;
    for (j = k; j <= (i - k - 1) / 2.0; j++)
    {
        temp = str_num[j];
        str_num[j] = str_num[i - j - 1];
        str_num[i - j - 1] = temp;
    }
    return str_num;
}

typedef struct
{
    unsigned int count[2];          //Length of the number of bits to store the original information, up to 2^64 bits (lsb)
    unsigned int state[4];          //4 32-bit numbers that hold intermediate results or final summary information
    unsigned char buffer[64];   
}MD5_CTX; 

#define use_asm                      //For conditional compilation of assembly code

//F, G, H and I are the basic MD5 functions.
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))

#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))  //The integer X is cyclically shifted n bits to the left, shifting the high bit to the low bit

/* FF, GG, HH and II are the operation functions for rounds 1, 2, 3 and 4, respectively. Rotation is separated from addition to prevent recalculation. */
#define FF(a,b,c,d,x,s,ac) \
          { \
          a += F(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          } 

#define GG(a,b,c,d,x,s,ac) \
          { \
          a += G(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }

#define HH(a,b,c,d,x,s,ac) \
          { \
          a += H(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }

#define II(a,b,c,d,x,s,ac) \
          { \
          a += I(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }          

/*PADDING is used to extend the plaintext*/
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/*T[i] is the table of additive constants, which is the integer part of the 4294967296th power of the sine of i+1 (the array starts from T[0])*/
unsigned int T[64]={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
                    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
                    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
                    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
                    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
                    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
                    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
                    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

// char *PLAINTEXT_FILE = "plaintext.txt";
// int num_plaintext;

/* Initialization process*/
void MD5Initial(MD5_CTX *context)
{
#ifndef use_asm
    context->count[0] = 0;              //Set the length of the current valid message to 0
    context->count[1] = 0;
	//state?????????
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
#else
     __asm(
        "PUSH     {R4,LR}"                                      "\n\t"
        "MOVS     R4,R0"                                        "\n\t"
        "ADD      R3,R0,#+24"                                   "\n\t"
        "CMP      R0,R1"                                        "\n\t"

        "ITE      CS"                                           "\n\t"
        "CMPCS    R2,R3"                                        "\n\t"
        "MOVS     R1,#+0"                                       "\n\t"
        "STR      R1,[R0, #+0]"                                 "\n\t"
        "MOVS     R0,#+0"                                       "\n\t"
        "STR      R0,[R4, #+4]"                                 "\n\t"
        
        "LDR.N    R0,=0x67452301"                               "\n\t"
        "STR      R0,[R4, #+8]"                                 "\n\t"
        "LDR.N    R0,=0xefcdab89"                               "\n\t"
        "STR      R0,[R4, #+12]"                                "\n\t"
        "LDR.N    R0,=0x98badcfe"                               "\n\t"
        "STR      R0,[R4, #+16]"                                "\n\t"
        "LDR.N    R0,=0x10325476"                               "\n\t"
        "STR      R0,[R4, #+20]"                                "\n\t"
        "POP      {R4,PC}          ;; return"                   "\n\t"
     );
     #endif
}

/* Convert input from a 4-byte integer to unsigned char format output */
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{   
    unsigned int i,j;
    for(j=0,i=0;j<len;j=j+4,i=i+1)
    {   
        output[j] = input[i] & 0xFF;  
        output[j+1] = (input[i] >> 8) & 0xFF;
        output[j+2] = (input[i] >> 16) & 0xFF;
        output[j+3] = (input[i] >> 24) & 0xFF;
    }
}

/* Convert input from unsigned char to 4-byte integer format output */
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
    unsigned int i,j;
    for(j=0,i=0;j<len;j=j+4,i=i+1)
    {
        output[i] = (input[j]) | (input[j+1] << 8) | (input[j+2] << 16) | (input[j+3] << 24);
    }
}

/*Basic code to perform md5 conversion*/
void MD5Trans(unsigned int state[4],unsigned char block[64])
{
     unsigned int a = state[0];
     unsigned int b = state[1];
     unsigned int c = state[2];
     unsigned int d = state[3];
     unsigned int x[64];
     MD5Decode(x,block,64);

     //Number of LROTATE bits per 16 steps in a four-round cycle     7?12?17
     //Accumulation base for every 16 steps in a four-round cycle        0xd76aa478?0x242070db
/* Round 1 */
    FF(a, b, c, d, x[ 0], 7,  T[0]); /* 1 */
    FF(d, a, b, c, x[ 1], 12, T[1]); /* 2 */
    FF(c, d, a, b, x[ 2], 17, T[2]); /* 3 */
    FF(b, c, d, a, x[ 3], 22, T[3]); /* 4 */
    FF(a, b, c, d, x[ 4], 7,  T[4]); /* 5 */
    FF(d, a, b, c, x[ 5], 12, T[5]); /* 6 */
    FF(c, d, a, b, x[ 6], 17, T[6]); /* 7 */
    FF(b, c, d, a, x[ 7], 22, T[7]); /* 8 */
    FF(a, b, c, d, x[ 8], 7,  T[8]); /* 9 */
    FF(d, a, b, c, x[ 9], 12, T[9]); /* 10 */
    FF(c, d, a, b, x[10], 17, T[10]); /* 11 */
    FF(b, c, d, a, x[11], 22, T[11]); /* 12 */
    FF(a, b, c, d, x[12], 7,  T[12]); /* 13 */
    FF(d, a, b, c, x[13], 12, T[13]); /* 14 */
    FF(c, d, a, b, x[14], 17, T[14]); /* 15 */
    FF(b, c, d, a, x[15], 22, T[15]); /* 16 */
 
 /* Round 2 */
	GG(a, b, c, d, x[ 1], 5,  T[16]); /* 17 */
	GG(d, a, b, c, x[ 6], 9,  T[17]); /* 18 */
	GG(c, d, a, b, x[11], 14, T[18]); /* 19 */
	GG(b, c, d, a, x[ 0], 20, T[19]); /* 20 */
	GG(a, b, c, d, x[ 5], 5,  T[20]); /* 21 */
	GG(d, a, b, c, x[10], 9,  T[21]); /* 22 */
	GG(c, d, a, b, x[15], 14, T[22]); /* 23 */
	GG(b, c, d, a, x[ 4], 20, T[23]); /* 24 */
	GG(a, b, c, d, x[ 9], 5,  T[24]); /* 25 */
	GG(d, a, b, c, x[14], 9,  T[25]); /* 26 */
	GG(c, d, a, b, x[ 3], 14, T[26]); /* 27 */
	GG(b, c, d, a, x[ 8], 20, T[27]); /* 28 */
	GG(a, b, c, d, x[13], 5,  T[28]); /* 29 */
	GG(d, a, b, c, x[ 2], 9,  T[29]); /* 30 */
	GG(c, d, a, b, x[ 7], 14, T[30]); /* 31 */
	GG(b, c, d, a, x[12], 20, T[31]); /* 32 */
 
 /* Round 3 */
	HH(a, b, c, d, x[ 5], 4,  T[32]); /* 33 */
	HH(d, a, b, c, x[ 8], 11, T[33]); /* 34 */
	HH(c, d, a, b, x[11], 16, T[34]); /* 35 */
	HH(b, c, d, a, x[14], 23, T[35]); /* 36 */
	HH(a, b, c, d, x[ 1], 4,  T[36]); /* 37 */
	HH(d, a, b, c, x[ 4], 11, T[37]); /* 38 */
	HH(c, d, a, b, x[ 7], 16, T[38]); /* 39 */
	HH(b, c, d, a, x[10], 23, T[39]); /* 40 */
	HH(a, b, c, d, x[13], 4,  T[40]); /* 41 */
	HH(d, a, b, c, x[ 0], 11, T[41]); /* 42 */
	HH(c, d, a, b, x[ 3], 16, T[42]); /* 43 */
	HH(b, c, d, a, x[ 6], 23, T[43]); /* 44 */
	HH(a, b, c, d, x[ 9], 4,  T[44]); /* 45 */
	HH(d, a, b, c, x[12], 11, T[45]); /* 46 */
	HH(c, d, a, b, x[15], 16, T[46]); /* 47 */
	HH(b, c, d, a, x[ 2], 23, T[47]); /* 48 */
 
 /* Round 4 */
	II(a, b, c, d, x[ 0], 6,  T[48]); /* 49 */
	II(d, a, b, c, x[ 7], 10, T[49]); /* 50 */
	II(c, d, a, b, x[14], 15, T[50]); /* 51 */
	II(b, c, d, a, x[ 5], 21, T[51]); /* 52 */
	II(a, b, c, d, x[12], 6,  T[52]); /* 53 */
	II(d, a, b, c, x[ 3], 10, T[53]); /* 54 */
	II(c, d, a, b, x[10], 15, T[54]); /* 55 */
	II(b, c, d, a, x[ 1], 21, T[55]); /* 56 */
	II(a, b, c, d, x[ 8], 6,  T[56]); /* 57 */
	II(d, a, b, c, x[15], 10, T[57]); /* 58 */
	II(c, d, a, b, x[ 6], 15, T[58]); /* 59 */
	II(b, c, d, a, x[13], 21, T[59]); /* 60 */
	II(a, b, c, d, x[ 4], 6,  T[60]); /* 61 */
	II(d, a, b, c, x[11], 10, T[61]); /* 62 */
	II(c, d, a, b, x[ 2], 15, T[62]); /* 63 */
	II(b, c, d, a, x[ 9], 21, T[63]); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/*MD5 block update operation. Continue the MD5 messages digest operation, process another message block, and update the context*/
void MD5New(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,remainder = 0,partlen = 0;
    /*Mod64 the number of its bytes and store it in the remainder*/
    /*That is, if bits mod 512 after less than 448, then padding*/
    remainder=(context->count[0] >> 3) & 0x3F;
    partlen=64-remainder;
    if((context->count[0]+=inputlen<<3)< (inputlen << 3))
    {
       context->count[1]++;
    }
    context->count[1]+=inputlen>>29;
    /* md5 conversion whenever possible*/
    i=0;
    if(inputlen>=partlen)
    {
       memcpy(&context->buffer[remainder],input,partlen);   //First store the Input into the buffer and make up
       MD5Trans(context->state,context->buffer);
       for(i=partlen;i+63<inputlen;i+=64)
           MD5Trans(context->state,&input[i]);
       remainder = 0;        
    }
    /* The value of the buffer is assigned again */
    memcpy(&context->buffer[remainder],&input[i],inputlen-i);
}

/*Total MD5 operation functions*/
void MD5ALL(MD5_CTX *context,unsigned char *input,unsigned char *output)
{   
    unsigned int index = 0,padlen = 0;
    unsigned char plain_bits[8];
    MD5Initial(context);
    MD5New(context,input,strlen((char *)input)); 
    index = ((context)->count[0] >> 3) & 0x3F;              //mod64
    padlen = (index < 56)?(56-index):(120-index);           //Number of complements required
    MD5Encode(plain_bits,(context)->count,8);               //Fetch the bit length of all original text
    MD5New((context),PADDING,padlen);                    
    MD5New((context),plain_bits,8);                      //Add the digits of the original text
    MD5Encode(output,(context)->state,16);
}

void plaintext_abstract(char *in_fn, char *out_fn)
{   
    int i,flen;
	unsigned char decrypt[16];
    // unsigned char k[16];
    unsigned char *inputchar;
    FILE*fp;
    fp=fopen(in_fn,"r");          // Open file
    fseek(fp,0L,SEEK_END);                  // Locate the end of the file 
    flen=ftell(fp);                         // Get the file size   
    inputchar=(unsigned char *)malloc(flen+1); // Dynamically allocate memory space based on file size 
    if(inputchar==NULL) 
    { 
    fclose(fp); 
    // return 0; 
    } 
    fseek(fp,0L,SEEK_SET); // Locate at the beginning of the file  
    fread(inputchar,flen,1,fp); // Read all file contents at once  
    inputchar[flen]=0; // End-of-string flag  
    fclose(fp);
	MD5_CTX md5;
    MD5ALL(&md5,inputchar,decrypt);
    fp=fopen(out_fn,"w+");
    // fprintf(fp,"Plaintext:\n%s\nCiphertext:\n",inputchar);
    for (i=4;i<=11;i++){
        fprintf(fp,"%02x",decrypt[i]);
    }
    free(inputchar);
    fclose(fp);
	// return 0;
}
void hardware_init()
{
    NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);//set interrupt priority level
	delay_init();	    	 //reset initial delay function
	uart_init(115200);	 // uart set
}

void algorithm_init()
{
    // initialize file name 

	strcpy(plaintext_fn,SOURCE_PATH);
	strcat(plaintext_fn,PLAINTEXT_NAME);

    strcpy(signature_fn,SOURCE_PATH);
	strcat(signature_fn,SIGNATURE_NAME);

    strcpy(ciphertext_fn_tx,SOURCE_PATH);
    strcat(ciphertext_fn_tx,CIPHERTEXT_NAME);

    strcpy(aeskey_orig_fn,SOURCE_PATH);
    strcat(aeskey_orig_fn,AESKEY_ORIG_NAME);

    strcpy(aeskey_init_vect_tx,SOURCE_PATH);
    strcat(aeskey_init_vect_tx,AESKEY_INIT_VECT_NAME);
    
    strcpy(aeskey_encr_fn_tx,SOURCE_PATH);
    strcat(aeskey_encr_fn_tx,AESKEY_ENCR_NAME);
    
    strcpy(aeskey_encr_fn_rx,DESTINATION_PATH);
    strcat(aeskey_encr_fn_rx,AESKEY_ENCR_NAME);

    strcpy(aeskey_init_vect_rx,DESTINATION_PATH);
    strcat(aeskey_init_vect_rx,AESKEY_INIT_VECT_NAME);

    strcpy(ciphertext_fn_rx,DESTINATION_PATH);
    strcat(ciphertext_fn_rx,CIPHERTEXT_NAME);
    
    strcpy(text_decr_fn,DESTINATION_PATH);
    strcat(text_decr_fn,PLAINTEXT_NAME);

    strcpy(abstract_fn_rx,DESTINATION_PATH);
    strcat(abstract_fn_rx,SIGNATURE_NAME);
    
    
    getKeyAndInitvect(aeskey_orig_fn,aeskey_init_vect_tx);
    // initialize rsa related parameters
}

void aeskey_encrypt(char *in_file, char *out_file)
{
    get_plaintext_set(plaintext_set);
    printf("Encrypting by RSA...\n");
    for (int i = 0; i < num_plaintext; i++)
    {
        pre_process(plaintext_set[i]);
        str_plaintext = show_plaintext(plaintext_set[i]);
        //printf("length=%d\n",strlen(str_plaintext));
        value_plaintext = divide_and_convert(str_plaintext, &num_section); // data_type array

        get_primes(&p, &q);
        get_n_PHIn(&n, &PHIn, p, q);

        myitoa(p, str_p, 10);
        myitoa(q, str_q, 10);
        myitoa(n, str_n, 10);
        myitoa(PHIn, str_PHIn, 10);
        get_e_d(&e, &d, PHIn);
        myitoa(e, str_e, 10);
        myitoa(d, str_d, 10);
        // printf("e = %s\n", str_e);
        // printf("d = %s\n", str_d);
        
        // value_decodedtext=(data_type*)calloc(num_section,sizeof(data_type)); // necessary
        for (int j = 0; j < num_section; j++)
        {
            char str_value_plaintext[MAX_LENGTH];
            // str_value_decodedtext[j]=(char*)calloc(8+1,sizeof(char)); // necessary
            //str_ciphertext[j]=(char*)malloc(20*sizeof(char));
            myitoa(value_plaintext[j], str_value_plaintext, 10);
            //printf("str_value_plaintext[%d] = %s\n", j, str_value_plaintext);
            ciphertext[i] = squ_mul(value_plaintext[j], e, n);
            myitoa(ciphertext[i], str_ciphertext[j], 10);
            printf("str_ciphertext[%d] = %s\n", j, str_ciphertext[j]);
        }

        FILE *fp;
        if ((fp = fopen(out_file, "w")) == NULL)
        {
            printf("File open error!\n");
            exit(0);
        }
        for(int i=0;i<num_section;i++)
            fprintf(fp,"%s\n",str_ciphertext[i]);
        // fprintf(fp,"\n");
        if (fclose(fp))
        {
            printf("File close error!\n");
            exit(0);
        }

    }
}

void aeskey_decrypt(char *in_file)
{
    get_ciphertext_set(ciphertext_set);
    printf("Decrypting by RSA...\n");

    value_decodedtext=(data_type*)calloc(num_section,sizeof(data_type)); // necessary
    char str_value_plaintext[MAX_LENGTH];
    for (int j = 0; j < num_section; j++)
    {
        //str_value_decodedtext[j]=(char*)calloc(16+1,sizeof(char)); // necessary
        ciphertext[j]=0;
        for (int k=0;k<strlen(ciphertext_set[j]);k++)
            ciphertext[j]=10*ciphertext[j]+(ciphertext_set[j][k]-'0'); // string turns to data_type
        value_decodedtext[j] = squ_mul(ciphertext[j], d, n);
        myitoa(value_decodedtext[j], str_value_decodedtext[j], 10);
    }
    merge_and_convert(decodedtext,str_value_decodedtext);
    //printf("decodedtext = %s\n", decodedtext);
    // decodedtext_set[i]=(char*)malloc(sizeof(char)*MAX_LENGTH+1);
    // strcpy(decodedtext_set[i],decodedtext);
    // printf("decodedtext_set[%d] = %s\n",i,decodedtext_set[i]);
    printf("decodedtext = %s\n",decodedtext);
    de_aeskey = (char*)malloc(sizeof(char)*MAX_LENGTH);
    strcpy(de_aeskey,decodedtext); // to write into decrypted aeskey

    // for (int k=0; k<num_section;k++)
    //     free(str_value_decodedtext[k]);
    free(value_decodedtext);
    write_decodedtext_set(decodedtext_set);
    // here
    free(value_plaintext);
    for (int i = 0; i < num_plaintext; i++)
    {
        free(plaintext_set[i]);
    }
    //free(decodedtext);
}

// transmit files, including
// ciphertext_fn_tx, 
void transmit()
{
    FILE *src_file, *dest_file;
    char temp[TEMP_CHAR_LEN];
    uint16_t i;
    // cipher
    src_file = fopen(ciphertext_fn_tx, "r");
    dest_file = fopen(ciphertext_fn_rx, "w");
    fscanf(src_file,"%s",temp);
    fprintf(dest_file,"%s",temp);
    fclose(src_file);
    fclose(dest_file);

    // aeskey_encr
    src_file = fopen(aeskey_encr_fn_tx, "r");
    dest_file = fopen(aeskey_encr_fn_rx, "w");
    for (i = 0; i < 16; i++)
    {
        fscanf(src_file,"%s",temp);
        fprintf(dest_file,"%s\n",temp);
    }

    fclose(src_file);
    fclose(dest_file);
    
    // aes init vector
    src_file = fopen(aeskey_init_vect_tx, "r");
    dest_file = fopen(aeskey_init_vect_rx, "w");
    fscanf(src_file,"%s",temp);
    fprintf(dest_file,"%s",temp);
    fclose(src_file);
    fclose(dest_file);

    // signature
    src_file = fopen(signature_fn, "r");
    dest_file = fopen(abstract_fn_rx, "w");
    fscanf(src_file,"%s",temp);
    fprintf(dest_file,"%s",temp);
    fclose(src_file);
    fclose(dest_file);    
}

char abstract_decr[100] = {0};
int flag;

void decr_abstract(char *in_fn)
{
    int i,flen;
	unsigned char decrypt[16];
    // unsigned char k[16];
    unsigned char *inputchar;
    FILE*fp;
    fp=fopen(in_fn,"r");         
    fseek(fp,0L,SEEK_END);                  
    flen=ftell(fp);                        
    inputchar=(unsigned char *)malloc(flen+1); 
    if(inputchar==NULL) 
    { 
    fclose(fp); 
    // return 0; 
    } 
    fseek(fp,0L,SEEK_SET); 
    fread(inputchar,flen,1,fp); 
    inputchar[flen]=0;
    fclose(fp);
	MD5_CTX md5;
    MD5ALL(&md5,inputchar,decrypt);

    for (i=4;i<=11;i++){
        // sprintf(abstract_decr,"%02x",decrypt[i]);
        abstract_decr[i-4] = decrypt[i];
    } 
    free(inputchar);
	// return 0;
}



void verify(char name[]){
    char *inputchar;
    int flen;
    FILE*fp;
    fp=fopen(name,"r");          
    fseek(fp,0L,SEEK_END);                  
    flen=ftell(fp);                        
    inputchar=(char *)calloc(flen+1,1);
    // if(inputchar==NULL) 
    fseek(fp,0L,SEEK_SET); 
    fread(inputchar,flen,1,fp);   
    convert2Hex(inputchar);
    inputchar[flen/2]=0; 
    fclose(fp);
    flag=strcmp(abstract_decr,inputchar);
    flag=!flag;
    if (flag) printf("\nTransimit Succeeds!\n",flag);
}

int main(void)
{
    time_t start,finish;
    uint16_t t;
    start = clock();
    
    int error = 0;

    hardware_init();
    // algorithm init 
    algorithm_init();
    //fn=filename
    //implement md5, plaintext_fn->signature_fn
    plaintext_abstract(plaintext_fn, signature_fn);
    //implement aes to plaintext, plaintext_fn-ciphertext_fn
    plaintext_encrypt(plaintext_fn, ciphertext_fn_tx);  //encrypt plaintext
    //implement rsa to aes key, aeskey_orig_fn-aeskey_encr_fn
    aeskey_encrypt(aeskey_orig_fn, aeskey_encr_fn_tx);  //encrypt aeskey
    transmit();// including aes_encr_key, ciphertext, abstract
  
    aeskey_decrypt(aeskey_encr_fn_rx);// decrpyt to get aes key
    cipher_decrypt(ciphertext_fn_rx, text_decr_fn, aeskey_init_vect_rx);
    decr_abstract(text_decr_fn);
    verify(abstract_fn_rx);
    
    finish = clock();
    t=finish-start;
    printf("Duration time = %d ms.",t);
    return error;
}


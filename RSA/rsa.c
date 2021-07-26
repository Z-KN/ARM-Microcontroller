#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include "rsa.h"

//typedef int64_t data_type;
#define MAX_LENGTH 128
#define MAX_NUM_PLAINTEXT 20
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
data_type ciphertext;
data_type *value_decodedtext;

char str_p[MAX_LENGTH] = {0};
char str_q[MAX_LENGTH] = {0};
char str_n[MAX_LENGTH] = {0};
char str_PHIn[MAX_LENGTH] = {0};
char str_e[MAX_LENGTH] = {0};
char str_d[MAX_LENGTH] = {0};
char *plaintext_set[MAX_NUM_PLAINTEXT]={0};
// char plaintext_set[MAX_NUM_PLAINTEXT][MAX_LENGTH]={0}; why error?
char *str_plaintext;
char str_ciphertext[MAX_LENGTH] = {0};
char *str_value_decodedtext[MAX_LENGTH]; // store str of value decodedtext
char *decodedtext_set[MAX_NUM_PLAINTEXT]={0};
char *str_value_decodedtext[MAX_LENGTH];
char *decodedtext;
char *PLAINTEXT_FILE = "./RSA/plaintext.txt";
char *PRIME_FILE = "./RSA/primes.txt";
char *DECODEDTEXT_FILE = "./RSA/decodedtext.txt";
int num_plaintext;
int num_section; // number of section in each converted array

// char *myitoa(data_type num, char *str_num, int radix);
// void get_primes(data_type *p, data_type *q, const char *PRIME_FILE);
// void get_n_PHIn(data_type *n, data_type *PHIn, data_type p, data_type q);
// void get_e_d(data_type *e, data_type *d, data_type PHIn);
// // data_type get_encode_index(data_type PHIn);
// data_type mul_inv(data_type a, data_type b);
// data_type squ_mul(data_type x, data_type c, data_type n);
// void get_plaintext_set(char *plaintext_set[]);
// void pre_process(char *plaintext);
// char *show_plaintext(char *plaintext);
// data_type *divide_and_convert(char *plaintext, int *num_section);
// char *merge_and_convert(char *str_value_decodedtext[]);
// void write_decodedtext_set(char *decodedtext_set[]);

// int test_rsa(void);

// To get plaintext from file
void get_plaintext_set(char *plaintext_set[])
{
    FILE *fp;
    if ((fp = fopen(PLAINTEXT_FILE, "r")) == NULL)
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

// To write the decodedtext to file
void write_decodedtext_set(char *plaintext_set[])
{
    FILE *fp;
    if ((fp = fopen(DECODEDTEXT_FILE, "w")) == NULL)
    {
        printf("File open error!\n");
        exit(0);
    }
    for(int i=0;i<num_plaintext;i++)
        printf("%s\n",plaintext_set[i]);
    // here free
    for(int i=0;i<num_plaintext;i++)
        fputs(plaintext_set[i],fp);

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

char* merge_and_convert(char *str_value_decodedtext[])
{
    // eg, ["12345678","23456789"]
    char *decodedtext = (char *)malloc(MAX_LENGTH + 1);
    int i, j;
    for (i = 0; i < MAX_LENGTH + 1; i++)
        decodedtext[i] = 0;
    // char *merged_decodedtext = (char *)calloc(num_section,9*sizeof(char));
    char *merged_decodedtext = (char *)malloc(MAX_LENGTH*2+1);
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
    free(merged_decodedtext);
    return decodedtext;
}

// get two big primes, p, q from am existing prime file randomly
void get_primes(data_type *p, data_type *q, const char *PRIME_FILE)
{
    FILE *fp;
    if ((fp = fopen(PRIME_FILE, "r")) == NULL)
    {
        printf("File open error!\n");
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
    printf("The plaintext is \"%s\"\n", plaintext);
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

int test_rsa()
{
    get_plaintext_set(plaintext_set);
    printf("Start implementing RSA...\n");
    for (int i = 0; i < num_plaintext; i++)
    {
        pre_process(plaintext_set[i]);
        str_plaintext = show_plaintext(plaintext_set[i]);
        //printf("length=%d\n",strlen(str_plaintext));
        value_plaintext = divide_and_convert(str_plaintext, &num_section); // data_type array

        get_primes(&p, &q, PRIME_FILE);
        get_n_PHIn(&n, &PHIn, p, q);

        myitoa(p, str_p, 10);
        myitoa(q, str_q, 10);
        myitoa(n, str_n, 10);
        myitoa(PHIn, str_PHIn, 10);
        // printf("p = %s\n", str_p);
        // printf("q = %s\n", str_q);
        // printf("n = %s\n", str_n);
        // printf("PHIn = %s\n", str_PHIn);
        get_e_d(&e, &d, PHIn);
        myitoa(e, str_e, 10);
        myitoa(d, str_d, 10);
        // printf("e = %s\n", str_e);
        // printf("d = %s\n", str_d);
        
        value_decodedtext=(data_type*)calloc(num_section,sizeof(data_type)); // necessary
        for (int j = 0; j < num_section; j++)
        {
            char str_value_plaintext[MAX_LENGTH];
            str_value_decodedtext[j]=(char*)calloc(8+1,sizeof(char)); // necessary
            myitoa(value_plaintext[j], str_value_plaintext, 10);
            printf("str_value_plaintext[%d] = %s\n", j, str_value_plaintext);
            ciphertext = squ_mul(value_plaintext[j], e, n);
            myitoa(ciphertext, str_ciphertext, 10);
            printf("ciphertext[%d] = %s\n", j, str_ciphertext);
            value_decodedtext[j] = squ_mul(ciphertext, d, n);
            myitoa(value_decodedtext[j], str_value_decodedtext[j], 10);
            printf("value_decodedtext[%d] = %s\n", j, str_value_decodedtext[j]);
        }
        decodedtext = merge_and_convert(str_value_decodedtext);
        printf("decodedtext = %s\n", decodedtext);
        plaintext_set[i]=decodedtext;
    
        for (int k=0; k<num_section;k++)
            free(str_value_decodedtext[k]);
        free(value_decodedtext);
    }
    write_decodedtext_set(plaintext_set);    
    for (int i = 0; i < num_plaintext; i++)
        free(plaintext_set[i]);
    free(value_plaintext);
    return 0;
}
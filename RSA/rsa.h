#ifndef _RSA_H_
#define _RSA_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

typedef int64_t data_type;
#define MAX_LENGTH 128
#define MAX_NUM_PLAINTEXT 20
#define MAX_B_IN_LINE 1024

// global variable, for debug use in iar

// data_type p;
// data_type q;
// data_type n;
// data_type PHIn;
// data_type e;
// data_type d;
// data_type plaintext;
// data_type *value_plaintext;
// data_type ciphertext;
// data_type *value_decodedtext;

// char str_p[MAX_LENGTH] = {0};
// char str_q[MAX_LENGTH] = {0};
// char str_n[MAX_LENGTH] = {0};
// char str_PHIn[MAX_LENGTH] = {0};
// char str_e[MAX_LENGTH] = {0};
// char str_d[MAX_LENGTH] = {0};
// char *plaintext_set[MAX_NUM_PLAINTEXT]={0};
// // char plaintext_set[MAX_NUM_PLAINTEXT][MAX_LENGTH]={0}; why error?
// char *str_plaintext;
// char str_ciphertext[MAX_LENGTH] = {0};
// char *str_value_decodedtext[MAX_LENGTH]; // store str of value decodedtext
// char *decodedtext_set[MAX_NUM_PLAINTEXT]={0};
// char *str_value_decodedtext[MAX_LENGTH];
// char *decodedtext;
// char *PLAINTEXT_FILE = "plaintext.txt";
// char *PRIME_FILE = "primes.txt";
// char *DECODEDTEXT_FILE = "decodedtext.txt";
// int num_plaintext;
// int num_section; // number of section in each converted array

char *myitoa(data_type num, char *str_num, int radix);
void get_primes(data_type *p, data_type *q, const char *PRIME_FILE);
void get_n_PHIn(data_type *n, data_type *PHIn, data_type p, data_type q);
void get_e_d(data_type *e, data_type *d, data_type PHIn);
// data_type get_encode_index(data_type PHIn);
data_type mul_inv(data_type a, data_type b);
data_type squ_mul(data_type x, data_type c, data_type n);
void get_plaintext_set(char *plaintext_set[]);
void pre_process(char *plaintext);
char *show_plaintext(char *plaintext);
data_type *divide_and_convert(char *plaintext, int *num_section);
char *merge_and_convert(char *str_value_decodedtext[]);
void write_decodedtext_set(char *decodedtext_set[]);

int test_rsa(void);

// // To get plaintext from file
// void get_plaintext_set(char *plaintext_set[]);
// // To write the decodedtext to file
// void write_decodedtext_set(char *plaintext_set[]);

// void pre_process(char *plaintext);

// data_type *divide_and_convert(char *plaintext, int *num_section);

// char* merge_and_convert(char *str_value_decodedtext[]);

// // get two big primes, p, q from am existing prime file randomly
// void get_primes(data_type *p, data_type *q, const char *PRIME_FILE);

// // get n and PHIn according to determined p and q
// void get_n_PHIn(data_type *n, data_type *PHIn, data_type p, data_type q);

// // Judge whether a and b is coprimes
// // if return 0, it means a gcd(a,b)!=0
// // else it returns the multiplication inverse of b^(-1) mod a
// // return d if it exists
// data_type mul_inv(data_type a, data_type b);

// // calculate x**c mod n
// data_type squ_mul(data_type x, data_type c, data_type n);

// void get_e_d(data_type *e, data_type *d, data_type PHIn);
// char *show_plaintext(char *plaintext);
// // To implement the non-standard functino itoa in c library
// char *myitoa(data_type num, char *str_num, int radix);

#endif
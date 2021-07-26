#ifndef _MD5_H_
#define _MD5_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    unsigned int count[2];          /* number of bits, modulo 2^64 (lsb first) */
    unsigned int state[4];
    unsigned char buffer[64];   
}MD5_CTX; 

#define MAX_B_IN_LINE 1024
#define MAX_LENGTH 128

//F，G，H和I是基本MD5函数.
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))

#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))  //整数X向左循环移n位，将高位移至低位

/* FF，GG，HH和II分别是第1、2、3、4轮的操作函数。旋转与加法分开，以防止重新计算。 */
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

/* 初始化过程*/
void MD5Initial(MD5_CTX *context);

/* 将输入从UINT4转换成unsigned char格式输出*/
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);

/* 将输入从unsigned char转换成UINT4格式输出*/
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);

/*进行md5转换的基本代码*/
void MD5Transform(unsigned int state[4],unsigned char block[64]);

/*MD5块更新操作。继续MD5消息摘要操作，处理另一个消息块，并更新上下文*/
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen);


//读文件
/*
void get_plaintext_set(char *plaintext_set[]);
*/
int test_md5();
#endif
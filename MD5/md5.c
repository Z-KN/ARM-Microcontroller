#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    unsigned int count[2];          //存储原始信息的bits数长度，最长为 2^64 bits（lsb）
    unsigned int state[4];
    unsigned char buffer[64];   
}MD5_CTX; 

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

//PADDING用于扩展明文
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

char *PLAINTEXT_FILE = "plaintext.txt";
int num_plaintext;

/* 初始化过程*/
void MD5Initial(MD5_CTX *context)
{
    context->count[0] = 0;              //将当前的有效信息的长度设成0
    context->count[1] = 0;
	//state中先存四个初始幻数
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

/* 将输入从UINT4转换成unsigned char格式输出*/
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
         output[j] = input[i] & 0xFF;  
         output[j+1] = (input[i] >> 8) & 0xFF;
         output[j+2] = (input[i] >> 16) & 0xFF;
         output[j+3] = (input[i] >> 24) & 0xFF;
         i++;
         j+=4;
    }
}

/* 将输入从unsigned char转换成UINT4格式输出*/
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
     unsigned int i = 0,j = 0;
     while(j < len)
     {
           output[i] = (input[j]) |
                       (input[j+1] << 8) |
                       (input[j+2] << 16) |
                       (input[j+3] << 24);
           i++;
           j+=4; 
     }
}

/*进行md5转换的基本代码*/
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
     unsigned int a = state[0];
     unsigned int b = state[1];
     unsigned int c = state[2];
     unsigned int d = state[3];
     unsigned int x[64];
     MD5Decode(x,block,64);

     //四轮循环中每16步的LROTATE位数     7、12、17
     //四轮循环中每16步的累加基数        0xd76aa478、0x242070db
/* Round 1 */
    FF(a, b, c, d, x[ 0], 7,  0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], 7,  0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], 7,  0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], 7,  0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */
 
 /* Round 2 */
	GG(a, b, c, d, x[ 1], 5,  0xf61e2562); /* 17 */
	GG(d, a, b, c, x[ 6], 9,  0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[ 5], 5,  0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
	GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[ 9], 5,  0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], 9,  0xc33707d6); /* 26 */
	GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], 5,  0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[ 2], 9,  0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */
 
 /* Round 3 */
	HH(a, b, c, d, x[ 5], 4,  0xfffa3942); /* 33 */
	HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[ 1], 4,  0xa4beea44); /* 37 */
	HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], 4,  0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[ 6], 23, 0x04881d05); /* 44 */
	HH(a, b, c, d, x[ 9], 4,  0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */
 
 /* Round 4 */
	II(a, b, c, d, x[ 0], 6,  0xf4292244); /* 49 */
	II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], 6,  0x655b59c3); /* 53 */
	II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[ 8], 6,  0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[ 4], 6,  0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/*MD5块更新操作。继续MD5消息摘要操作，处理另一个消息块，并更新上下文*/
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,remainder = 0,partlen = 0;
    /*对其字节的数目进行mod64，存入remainder*/
    remainder = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - remainder;
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3))
       context->count[1]++;
    context->count[1] += inputlen >> 29;
    /* 尽可能进行md5转换*/
    if(inputlen >= partlen)
    {
       memcpy(&context->buffer[remainder],input,partlen);
       MD5Transform(context->state,context->buffer);
       for(i = partlen;i+64 <= inputlen;i+=64)
           MD5Transform(context->state,&input[i]);
       remainder = 0;        
    }  
    else
    {
        i = 0;
    }
    /* 缓存区的值再次赋值 */
    memcpy(&context->buffer[remainder],&input[i],inputlen-i);
}

/*MD5操作总函数*/
void MD5ALL(MD5_CTX *context,unsigned char *input,unsigned char *output)
{   
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];
    MD5Initial(context);
	MD5Update(context,input,strlen((unsigned char *)input)); 
    index = ((context)->count[0] >> 3) & 0x3F;               //mod64
    padlen = (index < 56)?(56-index):(120-index);         //需要补全的个数
    MD5Encode(bits,(context)->count,8);
    MD5Update((context),PADDING,padlen);
    MD5Update((context),bits,8);
    MD5Encode(output,(context)->state,16);
}

void MD5FINAL(char name[],char out_name[])
{   
    int i,flen;
	unsigned char decrypt[16];
    unsigned char k[16];
    unsigned char *inputchar;
    FILE*fp;
    fp=fopen(name,"rb");          // 打开文件  
    fseek(fp,0L,SEEK_END);                  // 定位到文件末尾 
    flen=ftell(fp);                         // 得到文件大小  
    inputchar=(unsigned char *)malloc(flen+1); // 根据文件大小动态分配内存空间  
    if(inputchar==NULL) 
    { 
    fclose(fp); 
    exit (0);  
    } 
    fseek(fp,0L,SEEK_SET); // 定位到文件开头  
    fread(inputchar,flen,1,fp); // 一次性读取全部文件内容  
    inputchar[flen]=0; // 字符串结束标志  
    fclose(fp);
	MD5_CTX md5;
    MD5ALL(&md5,inputchar,decrypt);
    fp=fopen(out_name,"w+");
    //fprintf(fp,"Plaintext:\n%s\nCiphertext:\n",inputchar);
    for (i=4;i<=11;i++){
        fprintf(fp,"%02x",decrypt[i]);
    }
    free(inputchar);
    fclose(fp);
}

int main(){
    char a[80]="plaintext.txt";
    char b[80]="abstract.txt";
    MD5FINAL(a,b);
}
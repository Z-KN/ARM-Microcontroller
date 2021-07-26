#ifndef _AES_H_
#define _AES_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <time.h>

#define FILE_MAX_LENGTH ((uint32_t) AES_BLOCKLEN * 30)
#define HEX_FILE        1
#define PLAIN_TEXT      0

#define AES_KEY_FORMAT      HEX_FILE
#define AES_IV_FORMAT       HEX_FILE
#define AES_INPUT_FORMAT    PLAIN_TEXT
#define AES_ENCRY_FORMAT    HEX_FILE
#define AES_OUTPUT_FORMAT    PLAIN_TEXT

#define AES_MODE            "ecb"
#define AES_TIME_MEASURE    false
#define AES_DEBUG           true

//#define AES128 1
//#define AES192 1
#define AES256 1

//#define _MIX_ARM_       //micros determine whether inline assemly is used
//#define _EXT_ARM_       //micros determine whether assemly function is used

#define MULTIPLY_AS_FUNCTION 1
#if defined(AES256)
    #define key_len     32
#elif defined(AES192)
    #define key_len     24
#elif defined(AES128)
    #define key_len     16
#endif

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
};


void phex(uint8_t* str);

void encrypt_cbc(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length);
void decrypt_cbc(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length);
void xcrypt_ctr(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length);
void decrypt_ecb(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint16_t length);
void encrypt_ecb(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint16_t length);

void plaintext_encrypt(const char *inputFileName, const char *outputFileName);
void cipher_decrypt(const char *inputFileName, const char *outputFileName, const char *aes_initvect_fn);

uint8_t hexAsciiToNum(char c);
void GenerateInitVect(uint8_t * pInitvect);
int16_t readHexChar(FILE *inp);

void getKeyAndInitvect(const char *inKeyName, const char *inInitvectName);

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
void convert2Hex(uint8_t *hexIn2);

#endif //_AES_H_

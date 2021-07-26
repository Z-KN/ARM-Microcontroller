// This code implement AES algorithm, supporting ECB, CTR and CBC mode.
// available Block size choices are AES128, AES192, AES256.

// Includes
#include <stdint.h>
#include <string.h> 
#include "aes.h"

// Defines
#define Nb 4            // The number of columns comprising a state in AES

#if defined(AES256) && (AES256 == 1)
    #define Nk 8        // define number of 32 bit words in a key
    #define Nr 14       // define number of rounds in AES Cipher
    #define key_len     32
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
    #define key_len     24
#else
    #define Nk 4        
    #define Nr 10 
    #define key_len     16
#endif

// get the S-box value or reverse S-box value
#define getSBoxValue(num) (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])

// state - array holding the intermediate results during decryption
typedef uint8_t state_t[4][4];

uint8_t *pInitvect;
uint8_t *en_key;
extern uint8_t *de_aeskey ;
// The lookup-tables
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, contains the values of 
// power (i-1) being powers of x, or {02}, in the field GF(2^8)
static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// Private functions
// produces Nb(Nr+1) round keys to decrypt the states in each round
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
    unsigned i, j, k;
    uint8_t tmp_array[4]; 
    #if defined _MIX_ARM_
    uint32_t ch;
    #endif
    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i)
    {
    #ifndef _MIX_ARM_
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    #else
        asm volatile( 
        "ldr %[ch], [%[src],%[i],LSL #2]" "\n\t"
        "str %[ch], [%[des],%[i],LSL #2]" "\n\t"
        : [ch] "=&r" (ch)
        : [src]"r" (Key), [i] "r"(i)\
            [ch] "r" (ch), [des] "r" (RoundKey)
        : "memory"
        );
    #endif
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
    #ifndef _MIX_ARM_
        k = (i - 1) * 4;
        tmp_array[0] = RoundKey[k + 0];
        tmp_array[1] = RoundKey[k + 1];
        tmp_array[2] = RoundKey[k + 2];
        tmp_array[3] = RoundKey[k + 3];
    #else     
    asm volatile(
        "ldr %[ch], [%[src],%[i],LSL #2]" "\n\t"
        "str %[ch], [%[des]]" "\n\t"
        : [ch] "=&r" (ch)
        : [src]"r" (RoundKey), [i] "r"(i-1)\
            [ch] "r" (ch), [des] "r" (tmp_array)
        : "memory"
        );
    #endif

    if (i % Nk == 0)
    {
        // Function RotWord(), shifts the 4 bytes in a word to the left once.
        #ifndef _MIX_ARM_
        const uint8_t temp = tmp_array[0];
        tmp_array[0] = tmp_array[1];
        tmp_array[1] = tmp_array[2];
        tmp_array[2] = tmp_array[3];
        tmp_array[3] = temp;
        #else
        asm volatile(
            "ldr %[ch], [%[src]]" "\n\t"
            "mov %[ch], %[ch], ror #8" "\n\t"
            "str %[ch], [%[des]]" "\n\t"
            : [ch] "=&r" (ch)
            : [src] "r" (tmp_array), [ch] "r" (ch)\
                [des] "r" (tmp_array)
            : "memory"
            );
        #endif

        // Function Subword(), takes a four-byte input word 
        // and applies the S-box to each of the four bytes to produce an output word
        tmp_array[0] = getSBoxValue(tmp_array[0]);
        tmp_array[1] = getSBoxValue(tmp_array[1]);
        tmp_array[2] = getSBoxValue(tmp_array[2]);
        tmp_array[3] = getSBoxValue(tmp_array[3]);

        tmp_array[0] = tmp_array[0] ^ Rcon[i/Nk];
    }

    #if defined(AES256) && (AES256 == 1)
        if (i % Nk == 4)
        {
            // Function Subword()
            tmp_array[0] = getSBoxValue(tmp_array[0]);
            tmp_array[1] = getSBoxValue(tmp_array[1]);
            tmp_array[2] = getSBoxValue(tmp_array[2]);
            tmp_array[3] = getSBoxValue(tmp_array[3]);
        }
    #endif

        j = i * 4;
        k = (i - Nk) * 4;

        RoundKey[j + 0] = RoundKey[k + 0] ^ tmp_array[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tmp_array[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tmp_array[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tmp_array[3];
    }
}

// do the initial key expand
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
    KeyExpansion(ctx->RoundKey, key);
}

// AES_init_ctx_iv do the initial key expand with init vector
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}

// AddRoundKey function adds the round key to state by an XOR function.
static void AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey)
{
    uint8_t i,j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j) //it can be accelerate****************************
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
}

// SubBytes function substitutes the values in the state matrix with values in S-box.
static void SubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)//it can be accelerate****************************
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
}

// ShiftRows() function shifts the rows in the state to the left.
static void ShiftRows(state_t* state)
{
    uint8_t temp;
    #ifndef _MIX_ARM_
    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;

    #else 
       // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;

  #endif
}

// xtime function
#ifndef _EXT_ARM_
static uint8_t xtime(uint8_t x)
{
#ifndef _MIX_ARM_
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
#else //not an accelerate method
    uint8_t result, tmp;
    asm volatile(
        "lsr %[result], %[src], #7" "\n\t"
        "mov %[tmp], #0x1b" "\n\t"
        "mul %[result], %[result], %[tmp]" "\n\t"
        "eor %[result], %[result], %[src], lsl #1" "\n\t"
        : [tmp] "=&r" (tmp), [result] "=&r" (result)
        : [src] "r" (x), [tmp] "r" (tmp)\
          [result] "r" (result)
    );
    return result;
#endif
}
#else
extern uint8_t xtime(uint8_t x);
#endif

// mix the columns of the state matrix
static void MixColumns(state_t* state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t   = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_FUNCTION
  #ifndef _EXT_ARM_
  static uint8_t Multiply(uint8_t x, uint8_t y)
  {
      /*
    return (((y & 1) * x) ^
            ((y>>1 & 1) * xtime(x)) ^
            ((y>>2 & 1) * xtime(xtime(x))) ^
            ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); // this last call to xtime() can be omitted
        */
    uint8_t tmp;
	uint8_t result;
	result = (y & 1) * x;
	tmp = xtime(x);
	result ^= (y>>1 & 1) * tmp;
	tmp = xtime(tmp);
	result ^= (y>>2 & 1) * tmp;
	tmp = xtime(tmp);
	result ^= (y>>3 & 1) * tmp;
  	return result;
  }
  #else
    extern uint8_t Multiply(uint8_t x, uint8_t y);
  #endif
#else
    #define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         
#endif

// mixes the columns of the state matrix.
static void InvMixColumns(state_t* state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// recover the values in the state matrix from values in reverse S-box.
static void InvSubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
}

// undo the row shift
static void InvShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

// encrypt the plain text 
static void Cipher(state_t* state, uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(round, state, RoundKey);

    // The first Nr-1 rounds
    for (round = 1; round < Nr; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // The last round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

// Inverse Cipher for decrypt
static void InvCipher(state_t* state,uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr, state, RoundKey);

    // The first Nr-1 rounds
    for (round = (Nr - 1); round > 0; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }

    // The last round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

// xor the buffer with initvect
static void XorWithIv(uint8_t* buf, uint8_t* Iv)
{
    #ifndef _MIX_ARM_
    for (uint8_t i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
        buf[i] ^= Iv[i];
    #else
    uint32_t i = 0;   
    uint32_t x, y;
    __asm( 
        "xorwithiv_inline: ldr %[x], [%[src], %[i], lsl #2]"        "\n\t"
        "ldr %[y], [%[des], %[i], lsl #2]"        "\n\t"
        "eor %[x], %[x], %[y]"                "\n\t"
        "str %[x], [%[des], %[i], lsl #2]"              "\n\t"
        "add %[i], %[i], #1"            "\n\t"
        "cmp %[i], #4"                  "\n\t"
        "bne xorwithiv_inline"                 "\n\t"
        : [x]"=r"(x), [y]"=r"(y), [i] "=r"(i)
        : [src]"r" (Iv), [i] "r"(i)\
        [des] "r" (buf)
        : "memory"
    );
    #endif
}

// generate initvector
static void GenerateInitVect(uint8_t * pInitvect)
{
    srand(time(0));
    uint8_t i;
    for(i = 0; i< 16; i++)
        pInitvect[i] = rand() % 256;
}

// encrypt_ecb encrypt input plaintext in ECB mode
void encrypt_ecb(struct AES_ctx* pctx,uint8_t* en_key, uint8_t* in, uint16_t length)
{
    AES_init_ctx(pctx, en_key);
    for (uint16_t i = 0; i < length/16 ; i++)
        Cipher((state_t*)(in + 16 * i), pctx->RoundKey);
}

// decrypt_ecb decrypt input cipher text in ECB mode
void decrypt_ecb(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint16_t length)
{
    AES_init_ctx(pctx, key);
    for (uint16_t i = 0; i < length/16 ; i++)
        InvCipher((state_t*)(in + 16 * i), pctx->RoundKey);
}

// encrypt input plaintext in CBC mode
void encrypt_cbc(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length)
{
    // uintptr_t i;
    uint32_t i;
    uint8_t *Iv = iv;
    AES_init_ctx_iv(pctx, key, iv);

    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        XorWithIv(in, Iv);
        Cipher((state_t*)in, pctx->RoundKey);
        Iv = in;
        in += AES_BLOCKLEN;
    }
    /* store Iv in ctx for next call */
    memcpy(pctx->Iv, Iv, AES_BLOCKLEN);
}

// encrypt input plaintext in CBC mode
void decrypt_cbc(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length)
{
    AES_init_ctx_iv(pctx, key, iv);
    // uintptr_t i;
    uint32_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, in, AES_BLOCKLEN);
        InvCipher((state_t*)in, pctx->RoundKey);
        XorWithIv(in, pctx->Iv);
        memcpy(pctx->Iv, storeNextIv, AES_BLOCKLEN);
        in += AES_BLOCKLEN;
    }
}

// xrypt_ctr allow both encrypt and decrypt in CTR mode
void xcrypt_ctr(struct AES_ctx* pctx,uint8_t* key, uint8_t* in, uint8_t* iv, uint16_t length)
{
    int8_t bi;
    uint32_t i;
    uint8_t buffer[AES_BLOCKLEN];

    AES_init_ctx_iv(pctx, key, iv);

    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN) // regen xor compliment in buffer
        {
            memcpy(buffer, pctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer, pctx->RoundKey);
            /* Increment Iv and handle overflow */
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                if (pctx->Iv[bi] == 255)
                {
                    pctx->Iv[bi] = 0;
                    continue;
                }
                pctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }
        in[i] = (in[i] ^ buffer[bi]);
    }
}

// read a hexadecimal char in a file
int16_t readHexChar(FILE *inp)
{
    int16_t ch, result;
    ch = fgetc(inp);
    if (ch == EOF) return -1;
    else result = hexAsciiToNum(ch) * 16;
    ch = fgetc(inp);
    if (ch == EOF) return -1;
    else result += hexAsciiToNum(ch);
    return result;    
}

// convert a hexadecimal numberic char to number
uint8_t hexAsciiToNum(char c)
{
    unsigned char  rtVal = 0;
    if(c >= '0' && c <= '9')
        rtVal = c - '0';
    else if(c >= 'a' && c <= 'f')
        rtVal = c - 'a' + 10;
    else if(c >= 'A' && c <= 'F')
        rtVal = c - 'A' + 10;
    return rtVal;
}

// prints 16 char numeric string in a line to terminal in hex format
void phex(uint8_t* str)
{
    uint8_t i;
    for (i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

// get the key from file and generate initvect
void getKeyAndInitvect(const char *inKeyName, const char *inInitvectName)
{
    uint32_t i = 0;
    FILE *inkey, *inInitvect;

    //read key file
    inkey = fopen(inKeyName, "r");
    if (inkey == NULL) {
        // printf("Error opening Key File!\n");
        exit(1);
    }
    en_key = (uint8_t *)malloc(key_len * sizeof(char));
#if (AES_KEY_FORMAT  == HEX_FILE)
    for(i = 0; i < key_len; i++)
        *(en_key + i) = readHexChar(inkey);
#else
    for(i = 0; i < key_len; i++)
        *(en_key + i) = getc(inkey);
#endif
    fclose(inkey);

    #if (AES_DEBUG == true)
        printf("Key:\n");
        for(i = 0; i < key_len; i++)
            printf("%.2x", en_key[i]);
        printf("\n");
    #endif
    //read initvect
    inInitvect = fopen(inInitvectName,"w");
    if (inInitvect == NULL ) {
        // printf("Error creating InitVect File!\n");
        exit(1);
    }
    pInitvect = (uint8_t *)malloc(AES_BLOCKLEN * sizeof(uint8_t));
    GenerateInitVect(pInitvect);
#if (AES_IV_FORMAT  == HEX_FILE)
    for (i = 0; i < 16; i++)
        fprintf(inInitvect, "%.2x", pInitvect[i]);
#else
    for (i = 0; i < 16; i++)
        fputc(pInitvect[i], inInitvect);
#endif

    #if (AES_DEBUG == true)
        printf("Init vector:\n");
        for(i = 0; i < 16; i++)
            printf("%.2x", pInitvect[i]);
        printf("\n");
    #endif
    fclose(inInitvect);        
}

// encrypt input files and output files
void plaintext_encrypt(const char *inputFileName, const char *outputFileName)
{
    uint32_t i = 0;
    uint32_t count = 0;
    uint32_t length = 0;

    uint8_t* plain_text;
    FILE *inp, *out;

    int16_t ch;

    inp = fopen(inputFileName, "r");

    if (inp == NULL) {
        // printf("Error opening plaintext File!\n");
        exit(1);
    }
    while(length < FILE_MAX_LENGTH){
        ch = fgetc(inp);
        if (ch == -1) break;
        length++;
    }
    rewind(inp);
    count = (length + AES_BLOCKLEN - 1)/AES_BLOCKLEN;
    i = 0;
    plain_text = (uint8_t *)malloc(AES_BLOCKLEN * count * sizeof(uint8_t));
    while(i < count * 16)
    {
    #if (AES_INPUT_FORMAT == HEX_FILE)//read input file in hex format 
        ch = readHexChar(inp);
    #else   //read input file in plaintext
        ch = fgetc(inp);
    #endif
        if (ch == -1) plain_text[i++] = count * AES_BLOCKLEN - length;
        else plain_text[i++] = ch;
    }
    fclose(inp);

// print origin plaintext for debug
#if (AES_DEBUG == true)
    printf("Original Plain text:\n");
    for (int i = 0; i < (uint32_t) count; ++i)
        phex(plain_text + (i * 16));
#endif

    // part of encrypy
    struct AES_ctx ctx;
    // time measure option
#if (AES_TIME_MEASURE == true)
    time_t a, b;
    uint16_t t = 0;
    a = clock();
#endif

    // encrypt mode option
    if(AES_MODE == "ecb")
        encrypt_ecb(&ctx, en_key, plain_text,count * 16);
    else if(AES_MODE == "cbc")
        encrypt_cbc(&ctx, en_key, plain_text, pInitvect, count * 16);
    else if (AES_MODE == "ctr")
        xcrypt_ctr(&ctx, en_key, plain_text, pInitvect, count * 16);
    else
        encrypt_ecb(&ctx, en_key, plain_text, count * 16);

    // time measure option
#if (AES_TIME_MEASURE == true)
    b = clock();  
    t = b - a;
    printf("encrypt cost %d ms\n", t); 
#endif    

    // output encrypted file
    out = fopen(outputFileName,"w");
    for (i = 0; i < (uint32_t) count * 16; ++i)
    {
        #if (AES_ENCRY_FORMAT == HEX_FILE)
            fprintf(out, "%.2x", plain_text[i]);
        #else
            fputc(plain_text[i], out);       
        #endif
    }

    // print encrypted plaintext for debug
    #if (AES_DEBUG == true)
    printf("encrypt text:\n");
    for (int i = 0; i < (uint32_t) count; ++i)
        phex(plain_text + (i * 16));
    #endif

    fclose(out);
    free(pInitvect);
    free(plain_text);
}

void convert2Hex(uint8_t hexIn2[])
{
    int i;
    uint8_t ch;
    for(i = 0;i < key_len; i++)
    {
        ch = hexIn2[2*i];
        hexIn2[i] = hexAsciiToNum(ch) * 16;
        ch = hexIn2[2*i+1];
        hexIn2[i] += hexAsciiToNum(ch);
    }
}

// decrypt input files and output files
void cipher_decrypt(const char *inputFileName, const char *outputFileName, const char *aes_initvect_fn)
{
    uint32_t i = 0, j = 0;
    uint32_t count = 0;
    uint32_t length = 0;

    uint8_t* plain_text;
    FILE *inp, *out, *fInitVect;

    int16_t ch;

    inp = fopen(inputFileName, "r");

    // read encrpypted file
    if (inp == NULL) {
        // printf("Error in opening encrypted File!\n");
        exit(1);
    }
    // read char to get length of files
    while(length < FILE_MAX_LENGTH){
        #if (AES_ENCRY_FORMAT == HEX_FILE)
            ch = readHexChar(inp);
        #else
            ch = getc(inp);
        #endif
        if (ch == -1) break;
        length++;
    }
    rewind(inp);
    i = 0;
    // read the input file
    count = (length + 16 - 1)/16;
    plain_text = (uint8_t *)malloc(16 * count * sizeof(uint8_t));
    while(i < count * 16){
        #if (AES_ENCRY_FORMAT == HEX_FILE)
            ch = readHexChar(inp);
        #else
            ch = getc(inp);
        #endif
        if (ch == -1) plain_text[i++] = count * 16 - length;
        else plain_text[i++] = ch;
    }
    fclose(inp);

    #if (AES_DEBUG == true)
    printf("encrypted text:\n");
    for (int i = 0; i < (uint32_t) count; ++i)
        phex(plain_text + (i * 16));
    #endif
    
    convert2Hex(de_aeskey);
    #if(AES_DEBUG == true)
    printf("\n");
    #endif

    // read init vect file
    fInitVect = fopen(aes_initvect_fn,"r");
    if (fInitVect == NULL ) {
        // printf("Error reading InitVect File!\n");
        exit(1);
    }
    pInitvect = (uint8_t *)malloc(AES_BLOCKLEN * sizeof(uint8_t));
#if (AES_IV_FORMAT  == HEX_FILE)
    for (i = 0; i < 16; i++)
        pInitvect[i] = readHexChar(fInitVect);
#else
    for (i = 0; i < 16; i++)
        pInitvect[i] = getc(fInitVect);
#endif

#if(AES_DEBUG == true)
    printf("InitVector:\n");
    for (i = 0; i < 16; i++)
        printf("%.2x",pInitvect[i]);
    printf("\n");
#endif

    struct AES_ctx ctx;

#if (AES_TIME_MEASURE == true)
    time_t a, b;
    uint16_t t = 0;
    a = clock();
#endif
    if( AES_MODE == "ecb")
        decrypt_ecb(&ctx, de_aeskey, plain_text,count * 16);
    else if(AES_MODE == "cbc")
        decrypt_cbc(&ctx, de_aeskey, plain_text, pInitvect, count * 16);
    else if (AES_MODE == "ctr")
        xcrypt_ctr(&ctx, de_aeskey, plain_text, pInitvect, count * 16);
    else
        decrypt_ecb(&ctx, de_aeskey, plain_text,count * 16);
#if (AES_TIME_MEASURE == true)
    b = clock();  
    t = b - a;
    printf("decrypt cost %d ms\n", t); 
#endif    

    out = fopen(outputFileName,"w");

    for (i = 0; i < (uint32_t) count * 16; ++i)
    {
        // check whether there is padding
        if(plain_text[i] < AES_BLOCKLEN)
        {
            for(j = 0; j < plain_text[i] && i+j<count * 16; j++)
                if(plain_text[i+j] != plain_text[i] ) break;
            if(j == plain_text[i]) break;
        }
        
    #if (AES_OUTPUT_FORMAT == HEX_FILE)
        fprintf(out, "%.2x", plain_text[i]);
    #else
        fputc(plain_text[i], out);
    #endif    
    }

    #if (AES_DEBUG == true)
    printf("decrypt text:\n");
    for (int i = 0; i < (uint32_t) count; ++i)
        phex(plain_text + (i * 16));
    #endif
    fclose(out);
    free(plain_text);
}




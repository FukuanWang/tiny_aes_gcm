#include <stdint.h>

#ifndef _AES_GCM_H_
#define _AES_GCM_H_

//Using AES 128
#define AES_128

#ifdef AES_128
	#define Nk 4	//bytes per key
	#define Nb 4	//bytes per block
	#define Nr 10	//round times
	#define BL 16	//block length
	#define KL 16	//key length
#endif

//enable aes invcipher function
#define AES_INV_CIPHER


//typedef unsigned char uint8_t;
//typedef unsigned long uint32_t;

typedef uint8_t Blcok_128[BL];
typedef uint8_t Key_128[KL];
typedef uint8_t State[4][4];

//the definition of the word type
typedef struct {
	uint8_t a0;
	uint8_t a1;
	uint8_t a2;
	uint8_t a3;
} word;


#ifdef AES_128
	#define Block Blcok_128
	#define Key Key_128
#endif

typedef struct {
	word roundkey[Nb*(Nr + 1)];
	//byte* iv;
	Block J0;
	Block H;
}AES_ctx;


//#define xtime(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
#define xtime(x) (XTIME1[(x)])


//The constant within the algorithm for the block multiplication operation.
#define R 0xe1


//Change type from byte to uint32
#ifndef UINT32_TO_BYTE
	#define UINT32_TO_BYTE(ul,b)                \
	{										    \
		(b)[0] = (byte) ( (ul) >> 24 );         \
		(b)[1] = (byte) ( (ul) >> 16 );			\
		(b)[2] = (byte) ( (ul) >>  8 );			\
		(b)[3] = (byte) ( (ul)       );			\
	}
#endif


//judge if the i-th bit of X is zeros.
//(non-zero, if the reutrn value larger than 0)
#define VALUE(X,i) ((X)[(i) / 8] & (1 << (7 - i % 8)))

//ceil function of (num/den)
#ifndef ceil
	#define ceil(num,den) (((num) % (den) == 0) ? ((num) / (den)):((num) / (den) + 1))
#endif



/*====================================
	       public functions
======================================*/

/*
initialization of AES
including:
 -the key expansion.
*/
void AES_init(AES_ctx* ctx, const Key key);



/*
cipher the plain text using AES algorithm.
 -state should be a 2-dimensional uint_8 array.
 -length of plain text: 4*Nb bytes
 -length of cipher text: 4*Nb bytes
*/
void Cipher(State* state, const word roundkey[Nb * (Nr + 1)]);



#ifdef AES_INV_CIPHER
/*
Invcipher the cipher text using AES algorithm.
 -state should be a 2-dimensional uint_8 array.
 -length of plain text: 4*Nb bytes
 -length of cipher text: 4*Nb bytes
*/
void InvCipher(State* state, word* roundkey);
#endif


/*
initialization of AES_GCM
including:
 -the key expansion.
 -calculation of J0
 -calculation of H
*/
void AES_GCM_init(AES_ctx* ctx, const Key key, uint8_t* IV, uint32_t IVlen);


/*
cipher the plain text using AES-GCM.
Input parameters:
 -P:	  plain text
 -Plen: the length of the plain text. (bytes)
 -A:	  Authenticated data
 -Alen: the length of the Authenticated data.(bytes)
 -T:	  Authenticated Tag
 -Tlen: the length of the authenticated Tag. (bytes) T <= Block length
*/
void AES_GCM_cipher(const AES_ctx* ctx, uint8_t* P, uint32_t Plen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen);



/*
Decrpyt the cipher text using AES-GCM.
Input parameters:
 -C:	  cipher text
 -Plen: the length of the cipher text
 -A:	  Authenticated data
 -Alen: the length of the Authenticated data
 -T:	  Authenticated Tag
 -Tlen: the length of the authenticated Tag. T <= Block length(suppose that the size of IV, A, C are supported and len(T) = t);
output:
 -failed if return 0
 -success if return 1
*/
int AES_GCM_Invcipher(AES_ctx* ctx, uint8_t* C, uint32_t Clen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen);



#endif //_AES_GCM_H_

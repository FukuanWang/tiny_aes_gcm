#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include "aes_gcm.h"

#define TFuc(X) void X##_TEST(void)
#define InvT(X) X##_TEST()

#define ROUND 1000000

//const Key k = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
Block In = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
Key k = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
uint8_t IV[12] = { 0,0,0,0,0,0,0,0,0,0,0,0 };

/*
Functions that help to debug the programm
*/
void show_block(Block* b) {
	int i;
	for (i = 0; i < Nb * 4; i++) {
		printf("%02x", (unsigned int)(*b)[i]);
		if ((i + 1) % 4 == 0)
			printf(" ");
	}
	printf("\n");
}


void show_state(State s) {
	int r, c;
	for (r = 0; r < 4; r++) {
		for (c = 0; c < Nb; c++) {
			printf("%02x", (unsigned int)s[r][c]);
		}
		printf("\n");
	}
	printf("\n");
}

void show_bytes(uint8_t *b, uint32_t blen) {
	for (int i = 0; i < blen; i++) {
		printf("%02x", b[i]);
		if ((i + 1) % 4 == 0) {
			printf(" ");
		}
	}
	printf("\n");
}


void show_key(word rkey[4]) {
	int i;
	for (i = 0; i < Nb; i++) {
		printf("%02x", rkey[i].a0);
		printf("%02x", rkey[i].a1);
		printf("%02x", rkey[i].a2);
		printf("%02x", rkey[i].a3);
		printf(" ");
	}
	printf("\n");
}



TFuc(AES_GCM_cipher_Case1) {
	AES_ctx ctx;
	AES_GCM_init(&ctx, k, IV, 12);
	char *P = "";
	char *A = "";
	uint8_t T[16];
	AES_GCM_cipher(&ctx, (uint8_t *)P, 0, (uint8_t *)A, 0, T, 16);

	show_block((Block *)T);
}

TFuc(AES_GCM_cipher_Case2) {
	AES_ctx ctx;
	AES_GCM_init(&ctx, k, IV, 12);

	puts("H:");
	show_block(&(ctx.H));
	puts("J0:");
	show_block(&(ctx.J0));

	uint8_t P[BL];
	memset(P, 0, BL);


	char *A = "";
	uint8_t T[16];
	AES_GCM_cipher(&ctx, P, BL, (uint8_t *)A, 0, T, 16);

	puts("cipher text:");
	show_bytes(P, BL);

	puts("Tag:");
	show_block((Block *)T);
}

void Char2Hex(uint8_t *k, char *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		char temp1;
		char temp2;
		if (buf[2 * i] >= '0' && buf[2 * i] <= '9') {
			temp1 = buf[2 * i] - '0';
		}
		else if (buf[2 * i] >= 'a' && buf[2 * i] <= 'f') {
			temp1 = buf[2 * i] - 'a' + 10;
		}
		else {
			printf("buf must be a effective hex number!\n");
			exit(1);
		}
		if (buf[2 * i + 1] >= '0' && buf[2 * i + 1] <= '9') {
			temp2 = buf[2 * i + 1] - '0';
		}
		else if (buf[2 * i + 1] >= 'a' && buf[2 * i + 1] <= 'f') {
			temp2 = buf[2 * i + 1] - 'a' + 10;
		}
		else {
			printf("buf must be a effective hex number!\n");
			exit(1);
		}
		//printf("temp1=%d,temp2=%d\n", temp1, temp2);
		k[i] = (uint8_t)(temp1 * 16 + temp2);
	}
}

TFuc(AES_GCM_cipher_Case3) {

	/*parameter setting*/
	Key key;
	//byte miv[12];
	uint8_t* miv = (uint8_t *)malloc(12 * sizeof(uint8_t));
	if (miv == NULL) {
		exit(1);
	}
	Char2Hex((uint8_t*)key, "feffe9928665731c6d6a8f9467308308", KL);

	printf("befor:%d\n", miv);
	Char2Hex(miv, "cafebabefacedbaddecaf888", 12);
	printf("after:%d\n", miv);
	puts("key:");
	show_block((Block *)key);
	puts("iv:");
	for (int i = 0; i < 12; i++) {
		printf("%02x", miv[i]);
	}
	printf("\n");
	/*parameter setting*/

	AES_ctx ctx;
	AES_GCM_init(&ctx, key, miv, 12);

	puts("H:");
	show_block(&(ctx.H));
	puts("J0:");
	show_block(&(ctx.J0));

	uint32_t plen = 4 * BL;
	uint8_t *P = (uint8_t *)malloc(plen * sizeof(uint8_t));
	Char2Hex(P, "d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b391aafd255", plen);
	char *A = "";
	uint8_t T[16];
	AES_GCM_cipher(&ctx, P, plen, (uint8_t *)A, 0, T, 16);

	puts("cipher text:");
	show_bytes(P, BL);

	puts("Tag:");
	show_block((Block *)T);
}


TFuc(AES_GCM_cipher_Case4) {

	/*parameter setting*/
	Key key;
	uint8_t* miv = (uint8_t *)malloc(12 * sizeof(uint8_t));
	if (miv == NULL) {
		exit(1);
	}
	Char2Hex((uint8_t *)key, "feffe9928665731c6d6a8f9467308308", KL);

	//printf("befor:%d\n", miv);
	Char2Hex(miv, "cafebabefacedbaddecaf888", 12);
	//printf("after:%d\n", miv);
	puts("key:");
	show_block((Block *)key);
	puts("iv:");
	for (int i = 0; i < 12; i++) {
		printf("%02x", miv[i]);
	}
	printf("\n");
	/*parameter setting*/

	AES_ctx ctx;
	AES_GCM_init(&ctx, key, miv, 12);

	puts("H:");
	show_block(&(ctx.H));
	puts("J0:");
	show_block(&(ctx.J0));

	uint32_t plen = 4 * BL - 4;
	uint32_t alen = BL + 4;
	uint8_t *P = (uint8_t *)malloc(plen * sizeof(uint8_t));
	Char2Hex(P, "d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39", plen);
	uint8_t *A = (uint8_t *)malloc(alen * sizeof(uint8_t));
	Char2Hex(A, "feedfacedeadbeeffeedfacedeadbeefabaddad2", alen);
	uint8_t T[16];
	AES_GCM_cipher(&ctx, P, plen, A, alen, T, 16);

	puts("cipher text:");
	show_bytes(P, plen);

	puts("Tag:");
	show_block((Block *)T);
}

TFuc(AES_GCM_cipher_Case5) {

	/*parameter setting*/
	Key key;
	uint32_t IVlen = 8;
	uint8_t* miv = (uint8_t *)malloc(IVlen * sizeof(uint8_t));
	if (miv == NULL) {
		exit(1);
	}
	Char2Hex((uint8_t *)key, "feffe9928665731c6d6a8f9467308308", KL);

	printf("befor:%d\n", miv);
	Char2Hex(miv, "cafebabefacedbad", IVlen);
	printf("after:%d\n", miv);
	puts("key:");
	show_block((Block *)key);
	puts("iv:");
	for (int i = 0; i < 12; i++) {
		printf("%02x", miv[i]);
	}
	printf("\n");
	/*parameter setting*/

	AES_ctx ctx;
	AES_GCM_init(&ctx, key, miv, IVlen);

	puts("H:");
	show_block(&(ctx.H));
	puts("J0:");
	show_block(&(ctx.J0));

	uint32_t plen = 4 * BL - 4;
	uint32_t alen = BL + 4;
	uint8_t *P = (uint8_t *)malloc(plen * sizeof(uint8_t));
	Char2Hex(P, "d9313225f88406e5a55909c5aff5269a"	\
		"86a7a9531534f7da2e4c303d8a318a72"	\
		"1c3c0c95956809532fcf0e2449a6b525"	\
		"b16aedf5aa0de657ba637b39", plen);
	uint8_t *A = (uint8_t *)malloc(alen * sizeof(uint8_t));
	Char2Hex(A, "feedfacedeadbeeffeedfacedeadbeefabaddad2", alen);
	uint8_t T[16];
	AES_GCM_cipher(&ctx, P, plen, A, alen, T, 16);

	puts("cipher text:");
	show_bytes(P, plen);

	puts("Tag:");
	show_block((Block *)T);
}


TFuc(AES_GCM_cipher_Case6) {

	/*parameter setting*/
	Key key;
	uint32_t IVlen = 4 * BL - 4;
	uint8_t* miv = (uint8_t *)malloc(IVlen * sizeof(uint8_t));
	if (miv == NULL) {
		exit(1);
	}
	Char2Hex((uint8_t*)key, "feffe9928665731c6d6a8f9467308308", KL);
	Char2Hex(miv, "9313225df88406e555909c5aff5269aa"
		"6a7a9538534f7da1e4c303d2a318a728"
		"c3c0c95156809539fcf0e2429a6b5254"
		"16aedbf5a0de6a57a637b39b", IVlen);

	puts("key:");
	show_block((Block *)key);
	puts("\niv:");
	//for (int i = 0; i < 12; i++) {
	//	printf("%02x", miv[i]);
	//}
	show_bytes(miv, IVlen);
	printf("\n");
	/*parameter setting*/

	AES_ctx ctx;
	AES_GCM_init(&ctx, key, miv, IVlen);

	puts("\nH:");
	show_block(&(ctx.H));
	puts("\nJ0:");
	show_block(&(ctx.J0));

	uint32_t plen = 4 * BL - 4;
	uint32_t alen = BL + 4;
	uint8_t *P = (uint8_t *)malloc(plen * sizeof(uint8_t));
	Char2Hex(P, "d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39", plen);
	uint8_t *A = (uint8_t *)malloc(alen * sizeof(uint8_t));
	Char2Hex(A, "feedfacedeadbeeffeedfacedeadbeefabaddad2", alen);
	uint8_t T[16];

	puts("\nplain text:");
	show_bytes(P, plen);

	AES_GCM_cipher(&ctx, P, plen, A, alen, T, 16);

	puts("\ncipher text:");
	show_bytes(P, plen);

	puts("\nTag:");
	show_block((Block *)T);


	int ret = AES_GCM_Invcipher(&ctx, P, plen, A, alen, T, 16);
	if (ret) {
		puts("\nsuccess invcipher!, invcipher text:");
		show_bytes(P, plen);
	}
	else {
		puts("\ninvcipher failed!");
	}
}

TFuc(TimeTest){
    printf("AES_TIME_TEST_BEGIN");
    uint32_t IVlen = 12;
    Key key = { 0x69,0x38,0x6a,0xfc,0x52,0xd0,0x5b,0x2c,0xde,0x10,0x3d,0xd9,0x7f,0x58,0x27,0xe6 };
    uint8_t iv[] = { 0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88 };
    clock_t t1,t2;
    uint8_t st[16];
    AES_ctx ctx;
    uint8_t aesKey[16];
    memset(aesKey,0,16);


    t1 = clock();
    AES_init(&ctx, aesKey);
    t2 = clock();
    printf("time of AES_init: %d \n",(int)((t2-t1)));

    /*time of Cipher(1000 times)*/
    memset(st,0,16);
    int j=0;
    t1 = clock();
    for(j=0;j<ROUND;j++)
    Cipher((State*)st,ctx.roundkey);
    t2 = clock();
    printf("soft(cipher): ");
    for(j=0;j<16;j++){
     printf("%x ",st[j]);
    }
    printf("time of Cipher: %d \n",(int)((t2-t1)));

    /*time of InvCipher(1000 times)*/
    t1 = clock();
    for(j=0;j<ROUND;j++)
    InvCipher((State*)st,ctx.roundkey);
    t2 = clock();

    printf("soft(plain): ");
    for(j=0;j<16;j++){
     printf("%x ",st[j]);
    }
    printf("time of InvCipher: %d \n",(int)((t2-t1)));


    t1 = clock();
    AES_GCM_init(&ctx, key, iv, IVlen);
    t2 = clock();
    printf("time of AES_GCM_init: %d \n",(int)((t2-t1)));

    //char* app_buf = "hello_worldfajfdljslfjsldfjjdfalfjlsdfjladfjlafjasdf";
    char app_buf[500];
    memset(app_buf,0,1000);

    char* aad = "aad";
    uint8_t tag_buf[100];

    memset(app_buf,65,0);
    t1 = clock();
    for(j=0;j<ROUND;j++)
    AES_GCM_cipher(&ctx, (uint8_t *)app_buf, strlen(app_buf), (uint8_t *)aad, strlen(aad), tag_buf, 16);
    t2 = clock();
    printf("time of AES_GCM_cipher(0): %d \n",(int)((t2-t1)));

    memset(app_buf,65,50);
    t1 = clock();
    for(j=0;j<ROUND;j++)
    AES_GCM_cipher(&ctx, (uint8_t *)app_buf, strlen(app_buf), (uint8_t *)aad, strlen(aad), tag_buf, 16);
    t2 = clock();
    printf("time of AES_GCM_cipher(50): %d \n",(int)((t2-t1)));

    memset(app_buf,65,100);
    t1 = clock();
    for(j=0;j<ROUND;j++)
    AES_GCM_cipher(&ctx, (uint8_t *)app_buf, strlen(app_buf), (uint8_t *)aad, strlen(aad), tag_buf, 16);
    t2 = clock();
    printf("time of AES_GCM_cipher(100): %d \n",(int)((t2-t1)));

    memset(app_buf,65,150);
    t1 = clock();
    for(j=0;j<ROUND;j++)
    AES_GCM_cipher(&ctx, (uint8_t *)app_buf, strlen(app_buf), (uint8_t *)aad, strlen(aad), tag_buf, 16);
    t2 = clock();
    printf("time of AES_GCM_cipher(150): %d \n",(int)((t2-t1)));

    memset(app_buf,65,200);
    t1 = clock();
    for(j=0;j<ROUND;j++)
    AES_GCM_cipher(&ctx, (uint8_t *)app_buf, strlen(app_buf), (uint8_t *)aad, strlen(aad), tag_buf, 16);
    t2 = clock();
    printf("time of AES_GCM_cipher(200): %d \n",(int)((t2-t1)));
    double time;
    time=(double)((double)(t2-t1)/CLOCKS_PER_SEC);
    printf("CLOCKS_PER_SEC: %d",CLOCKS_PER_SEC);
    printf("last real time: %5.3f",time);

    printf("AES_TIME_TEST_END");
}

int main(void) {
    //InvT(AES_GCM_cipher_Case4);
    //InvT(AES_GCM_cipher_Case5);
	InvT(AES_GCM_cipher_Case6);
	//system("pause");
	return 0;
}



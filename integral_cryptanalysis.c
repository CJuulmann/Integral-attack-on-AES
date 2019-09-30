/* ========================================
	Integral cryptanalysis on 4-round AES:
	
	1) 	Choose 256 plaintext having equal values
	   	in 15 bytes and different values in one bye. 

	2)  Get the 256 ciphertexts; encrypted with a
		secret key using 4-rounds AES.
   ========================================*/

#include "sbox.h"
#include "aes.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// Function prototype



// Expanded key (using https://www.cryptool.org/en/cto-highlights/aes)
unsigned char roundkeys[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, //r0
	0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe, //r1
	0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe, //r2
	0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,	//r3
	0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd, //r4
};

// Input
unsigned char set1_plaintext[4096] = {[0 ... 4095] = 0x00 };
unsigned char set1_ciphertext[4096] = { 0x00 };

/*
unsigned char set2_plaintext[4096] = {[0 ... 4095] = 1 };
unsigned char set2_ciphertext[4096] = { 0 };

unsigned char set3_plaintext[4096] = {[0 ... 4095] = 2 };
unsigned char set3_ciphertext[4096] = { 0 };

unsigned char set4_plaintext[4096] = {[0 ... 4095] = 3 };
unsigned char set4_ciphertext[4096] = { 0 };
*/

void integral(unsigned char * ciphertext_set);

int main(){

	// Initialize chosen plaintexts with the first byte different
	int i;
	for(i=0; i<256; i++){
		//set1_plaintext[i*16] = i;
		set1_plaintext[i*16] = (unsigned char) i;
	}
	
	// Encrypt set1 plaintext and store in set1 ciphertext
	for(i=0; i<256; i++){
		AES_ENC(&set1_plaintext[i*16], roundkeys, &set1_ciphertext[i*16], S, 4);
		//AES_ENC(&set2_plaintext[i*16], roundkeys, &set2_ciphertext[i*16], S, 4);
	}
	
	// Run attack for chosen sets of ciphertexts
	integral(&set1_ciphertext[0]);
	
	
	return 0;
}


void integral(unsigned char * ciphertext_set){
	
	int i;
	unsigned char tmp[4096];
	
	// Copy ciphertext-set to local scope
	//memcpy(tmp, ciphertext_set, 4096);
	
	// Guessing roundkey on ciphertext-set
	int rk,ct;
	unsigned char roundkey_guess[16] = { 0x00 };
	unsigned char sum;
	unsigned char candidates[256] = {[0 ... 255] = 0x01 }; // Assume all are candidates and rule out 
	unsigned char tmp_candidates[256] = { 0 };
		
	// Searching roundkey-space on a single byte at a time for all ciphertexts
	for(rk=0; rk<256; rk++){
		
		// Copy ciphertext-set to local scope for each rk value
		memcpy(tmp, ciphertext_set, 4096);
		PrintState(tmp);
		sum = 0x00;	
		roundkey_guess[0] = (unsigned char) rk;

		// printf("roundkey_guess vector=");PrintState(roundkey_guess);
			
		// Searching with key guess on all ciphertexts values for one byte at a time
		for(ct=0; ct<256; ct++){
			// if(roundkey_guess[0] == 0x47){
			// printf("\nct=0x%x:\n", set1_ciphertext[ct*16]);
			// printf("before AddRoundKey: set1_ciphertext=0x%x\n", set1_ciphertext[ct*16]);
			
			AddRoundKey(roundkey_guess, &tmp[ct*16]);
			// printf("after AddRoundKey: set1_ciphertext=0x%x\n", set1_ciphertext[ct*16]);
			
			InvShiftRows(&tmp[ct*16]);
			// printf("after InvShiftRows: set1_ciphertext=0x%x\n", set1_ciphertext[ct*16]);
			
			SubBytes(&tmp[ct*16], SI);
			// printf("after InvSubBytes: set1_ciphertext=0x%x\n", set1_ciphertext[ct*16]);

			sum ^=tmp[ct*16];
			// printf("sum=%x\n", sum);
			
		 	// }
		}
		// If guessed round key (rk) computed on all values of CipherText sums to 0 then rk is a candidate
		if(sum == 0){
			tmp_candidates[rk] = 0x01;
		} else {
			tmp_candidates[rk] = 0x00;
		}
	}
	
	for(i=0; i<256; i++){
		candidates[i] *= tmp_candidates[i];
	}
	
	for(i=0; i<256; i++){
		printf("rk: 0x%x = 0x%x\t tmp = 0x%x\n", i, candidates[i], tmp_candidates[i]);
	}
	
}











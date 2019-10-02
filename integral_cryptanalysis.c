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
#include <stdlib.h>

// Function prototypes
void integral(unsigned char * ciphertext_set, int rk_byte_num);
int roundKeyFound(unsigned char * candidates, int n);
unsigned char * initPlaintextSet(unsigned char * plaintext_set, int constant);
unsigned char * resetCiphertextSet(unsigned char * ciphertext_set);

// Expanded key (using https://www.cryptool.org/en/cto-highlights/aes)
unsigned char roundkeys[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, //r0 (cipherkey)
	0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe, //r1
	0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe, //r2
	0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,	//r3
	0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd //r4
};

/*
unsigned char roundkeys2[] = {
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
	0x79, 0x72, 0x6e, 0x77, 0x72, 0x78, 0x67, 0x7f, 0x75, 0x7e, 0x62, 0x7b, 0x76, 0x7c, 0x63, 0x7b,
	0x6b, 0x89, 0x4f, 0x4f, 0x19, 0xf1, 0x28, 0x30, 0x6c, 0x8f, 0x4a, 0x4b, 0x1a, 0xf3, 0x29, 0x30,
	0x62, 0x2c, 0x4b, 0xed, 0x7b, 0xdd, 0x63, 0xdd, 0x17, 0x52, 0x29, 0x96, 0x0d, 0xa1, 0x00, 0xa6,
	0x58, 0x4f, 0x6f, 0x3a, 0x23, 0x92, 0x0c, 0xe7, 0x34, 0xc0, 0x25, 0x71, 0x39, 0x61, 0x25, 0xd7
};*/

// Input
unsigned char plaintext_set[4352] = { 0 };				// A set of 256 plaintexts of 16 bytes plus extra 256 bytes buffer, 256*16+256
unsigned char ciphertext_set[4352] = { 0 };

unsigned char candidates[256] = {[0 ... 255] = 0x01 }; // Assume all candidates and rule out as we integrate over multiple sets
unsigned char found_roundkey[16] = { 0 };			   // Last roundkey result
int rk_byte_num = 0;								   // Roundkey byte to be computed

int main(){
	int i, n;
	
	int c = 0;	// Constant value for plaintext set
	
	while(rk_byte_num < 16){
		
		// Make plaintext sets and search for roundkey byte until only one candidate left for that one byte
		while(!roundKeyFound(candidates, 1)){
			
			initPlaintextSet(plaintext_set, c);
		
			// Encrypt plaintext sets and save to corresponding ciphertext sets (16 bytes at a time)
			for(i=0; i<256; i++){
				AES_enc(&plaintext_set[i*16], roundkeys, &ciphertext_set[i*16], S, 4);
			}
		
			// Attack: find candidate for a single byte
			integral(ciphertext_set, rk_byte_num);
		
			// Reset ciphertext set in order to operate with a new one later
			c++;						//use incrementer as the one byte value that should differ in sets
			resetCiphertextSet(ciphertext_set);
		}	
		c = 0;	//reset constant for next ciphertext_sets for next iteration of rk_byte to find
		
		// Save found roundkey byte
		for(n=0; n<256; n++){
			if(candidates[n] == 0x1){
				found_roundkey[rk_byte_num] = n; // take index number as the rk value
				rk_byte_num++;					 // ready to find next byte of roundkey
				printf("0x%x\t", n);
				break;
			}
		}
		memset(candidates, 1, 256);		// reset
	}
	printf("\n");
	return 0;
}


// Function definitons
void integral(unsigned char * ciphertext_set, int rk_byte_num){
	
	int i, rk, ct;
	
	unsigned char tmp[4352];
	unsigned char roundkey_guess[16] = { 0x00 };
	
	unsigned char sum;
	unsigned char tmp_candidates[256] = { 0x0 };
		
	// Integrate for each round key (rk)
	for(rk=0; rk<256; rk++){
		
		// Copy ciphertext set to local scope for each rk value
		memcpy(tmp, ciphertext_set, 4352);
		
		// Initialize sum and round key guess for this loop-round
		sum = 0x00;	
		roundkey_guess[0] = (unsigned char) rk;
			
		// Compute with key guess on all ciphertexts values for one byte at a time
		for(ct=0; ct<256; ct++){
			
			// Compute backwards through last special round of AES
			addRoundKey(roundkey_guess, &tmp[ct*16+rk_byte_num]);				// addRoundKey is self-inverse		
			invShiftRows(&tmp[ct*16+rk_byte_num]);								// row i shifted i bytes to the right
			subBytes(&tmp[ct*16+rk_byte_num], SI);								// substitute using inverse S-box
			
			sum ^=tmp[ct*16+rk_byte_num];										// xor-summation of sub-results
		}
		
		// If guessed rk computed on all values of the ciphertext set sums to 0 then rk is a candidate
		if(sum == 0){
			tmp_candidates[rk] = 0x01;
		} else {
			tmp_candidates[rk] = 0x00;
		}
	}
	
	// Once done testing for each rk on the given ciphertext set, rule out candidates not in tmp_candidates
	for(i=0; i<256; i++){
		candidates[i] *= tmp_candidates[i];
	}
}

int roundKeyFound(unsigned char * candidates, int n){
	int i, sum;
	
	sum = 0;
	
	// candidates (cand) contain 0s and 1s; 1 => value is cand and 0 => value is not a cand
	for(i=0; i<256; i++){
		sum += candidates[i];
	}
	
	// If n candidates are found we are done
	if(sum == n)
		return 1;
	else
		return 0;
}

unsigned char * initPlaintextSet(unsigned char * plaintext_set, int constant){
	
	int i = 0;
	
	// Initialize chosen plaintexts with the i'th byte different rest as constant
	memset(plaintext_set, constant, 4352);
	for(i=0; i<256; i++){
		plaintext_set[i*16] = i;
	}
	
	return plaintext_set;
}

unsigned char * resetCiphertextSet(unsigned char * ciphertext_set){
	return memset(ciphertext_set, 0, 4352);
}











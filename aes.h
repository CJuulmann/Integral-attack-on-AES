/*
	Function prototypes
*/

#include <inttypes.h>

// Print state vector for debugging.
void PrintState(unsigned char * state);

/*
	AES Encryption
*/
void AES_ENC(unsigned char * plaintext, unsigned char * roundkey, unsigned char * state, unsigned char * M, unsigned char * S, uint8_t rounds);

void AddRoundKey(unsigned char * roundkey, unsigned char * state);
void SubBytes(unsigned char * state, unsigned char * S);
void ShiftRows(unsigned char * state);
unsigned char MulBy02(unsigned char * ptr);
void MixColumns(unsigned char * M, unsigned char * state);

/*
	AES Decryption
*/
void AES_DEC(unsigned char * plaintext, unsigned char * roundkey, unsigned char * state, unsigned char * M, unsigned char * S, uint8_t rounds);

void InvSubBytes(unsigned char * state, unsigned char * invS);
/*
	Function prototypes
*/
#include <inttypes.h>

// Print state vector for debugging.
void PrintState(unsigned char * state);

void AddRoundKey(unsigned char * roundkey, unsigned char * state);
void SubBytes(unsigned char * state, unsigned char * S);
void ShiftRows(unsigned char * state);
unsigned char MulBy02(unsigned char * ptr);
void MixColumns(unsigned char * M, unsigned char * state);
void AES_128(unsigned char * plaintext, unsigned char * roundkey, unsigned char * state, unsigned char * M, unsigned char * S, uint8_t rounds);
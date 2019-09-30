/*
	Function prototypes
*/

void printState(unsigned char * state);

void AES_enc(unsigned char * plaintext, unsigned char * roundkey, unsigned char * state, unsigned char * S, int rounds);

void addRoundKey(unsigned char * roundkey, unsigned char * state);

void subBytes(unsigned char * state, unsigned char * S);

void shiftRows(unsigned char * state);

void invShiftRows(unsigned char * state);

unsigned char mulBy02(unsigned char * ptr);

void mixColumns(unsigned char * M, unsigned char * state);


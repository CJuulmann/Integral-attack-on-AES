/*
	Function prototypes
*/

void PrintState(unsigned char * state);

void AES_ENC(unsigned char * plaintext, unsigned char * roundkey, unsigned char * state, unsigned char * S, int rounds);

void AddRoundKey(unsigned char * roundkey, unsigned char * state);

void SubBytes(unsigned char * state, unsigned char * S);

void ShiftRows(unsigned char * state);

void InvShiftRows(unsigned char * state);

unsigned char MulBy02(unsigned char * ptr);

void MixColumns(unsigned char * M, unsigned char * state);


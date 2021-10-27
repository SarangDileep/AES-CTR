//#include <stdint.h>
//
//  main.c
//  AES128
//
//  Created by Mihnea Stefan on 19/09/2020.
//  Copyright © 2020 Mihnea Stefan. All rights reserved.
//

#include "LookUpTables.h"
#include "AES128.h"
#include "CSHA512.h"
#include "PRNG.h"

/**
 * \brief Zeroes out the expanded key
 * 
 * This is invoked after completing the encryption process
 */
void cleanKeyExpansion() {
	for (int i = 0; i < 10; i++)
		for (int j = 0; j < KEY_SIZE; j++)
			expandedKey[i][j] = 0;
}

/**
 * \brief Increments the value of the nonce by one
 * 
 *  Used after handling each AES block 
 */
inline static void incrementNonce(uint8_t *nonce) {
	for (int i = 0; i < 16; i++)
		nonce[i]++;
}

/**
 * Encrypts the plaintext using AES-CTR
 * 
 * text - The user defined plaintext to be encrypted
 * encryption_key - The user defined encryption key
 * bytes - Number of bytes
 * 
 * As we're calling by reference, the ciphertext will be inside
 * the variable `text`
 *
 * Nonce is combined using concatenation by using memcpy() 
 */
void encryptionCTR(uint8_t *text, uint8_t *encryption_key, long bytes) {
	uint8_t *nonce = PRNG((char *)encryption_key);
	uint8_t _nonce[KEY_SIZE];
	long blocks = bytes / BLOCK_SIZE;

	keyExpansion(encryption_key);

	for (long i = 0; i < blocks; i++) {
		memcpy(_nonce, nonce, KEY_SIZE);
		encryptBlock(_nonce, encryption_key);
		addRoundKey(&text[i * BLOCK_SIZE], _nonce);
		incrementNonce(nonce);
	}

	free(nonce);
	cleanKeyExpansion();
}

/**
 * \brief Encrypts the plaintext using AES-CTR
 * 
 *  \param text - The user defined plaintext to be encrypted
 *  \encryption_key - The user defined encryption key
 *  \bytes - Number of bytes
 * 
 *  As we're calling by reference, the ciphertext will be inside
 *  the variable text
 */
FILE *searchForFilePlus(char *path, char *searchedItem) {
	char buffer[100];
	FILE *fp;
	fp = fopen(searchedItem, "w");

	printf("Please enter the %s:", searchedItem);
	scanf("%s", buffer);

	fprintf(fp, "%s", buffer);

	return fopen(searchedItem, "r");
}

long getFileSize(char *fileName) {
	struct stat fSize;
	stat(fileName, &fSize);
	return fSize.st_size;
}

/* **************************MAIN********************************** */

/*
    Execution begins in main(). 

    User interface, general memory management and the invocation of the
    function `encryptionCTR()` happens here.

    A buffer is malloc()-ed for storing the plaintext
*/
int main() {
	uint8_t padding = 0;
	uint8_t *buffer;
	int functionality;
	FILE *fileReader;
	FILE *keyReader;
	uint8_t key[BLOCK_SIZE];
	char outputName[20];
	char filePath[30];
	char keyPath[30];
	long fileSize;

	printf("\nSelect functionality\n1 - Encryption\n2 - Decryption\n");
	scanf("%d", &functionality);

	if (functionality != 1 && functionality != 2)
		return -1;

	if (!(fileReader = searchForFilePlus(filePath, "plaintext")) ||
		!(keyReader = searchForFilePlus(keyPath, "key "))) {
		return -1;
	}

	fread(key, 1, KEY_SIZE, keyReader);
	fclose(keyReader);
	fileSize = getFileSize(filePath);

	fileSize += BLOCK_SIZE;

	buffer = (uint8_t *)malloc((fileSize + padding) * sizeof(uint8_t));

	if (fileSize % BLOCK_SIZE != 0) {
		padding = (fileSize / BLOCK_SIZE + 1) * BLOCK_SIZE - fileSize;
		for (long i = fileSize; i < fileSize + padding; i++) // padding last block with white spaces
			buffer[i] = 32;
	}

	fread(buffer, 1, fileSize, fileReader);
	fclose(fileReader);

	encryptionCTR(buffer, key, fileSize + padding);

	printf("Ciphertext: %s", buffer);

	free(buffer);
	remove("plaintext");
	remove("key");

	return 0;
}
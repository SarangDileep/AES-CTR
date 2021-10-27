//
//  main.c
//  AES128
//

#include<stdint.h>
#include "LookUpTables.h"
#include "AES128.h"
#include "CSHA512.h"
#include "PRNG.h"

enum ModesOfOperation {
    ECB = 1,
    CBC = 2,
    OFB = 3,
    CTR = 4,
    CCM = 5
};

void cleanKeyExpansion(){
    for(int i=0;i<10;i++)
        for(int j=0;j<KEY_SIZE;j++)
            expandedKey[i][j] = 0;
}

inline static void incrementNonce(uint8_t *nonce){
    for(int i=0;i<16;i++)
        nonce[i]++;
}

void encryptionCTR(uint8_t *text, uint8_t *encryption_key, long bytes){
    uint8_t *nonce = PRNG((char*)encryption_key);
    uint8_t _nonce[KEY_SIZE];
    long blocks = bytes/BLOCK_SIZE;
    
    keyExpansion(encryption_key);
    
    for(long i = 0;i<blocks;i++){
        memcpy(_nonce, nonce, KEY_SIZE);
        encryptBlock(_nonce, encryption_key);
        addRoundKey(&text[i*BLOCK_SIZE], _nonce);
        incrementNonce(nonce);
    }

    free(nonce);
    cleanKeyExpansion();
}


FILE* searchForFilePlus(char* path, char* searchedItem){
        char buffer[100];
        FILE *fp;
        fp = fopen(searchedItem, "w");

        printf("Please enter the %s:", searchedItem);
        scanf("%s", buffer);

        fprintf(fp, "%s", buffer);

        return fopen(searchedItem, "r");
}

long getFileSize(char* fileName){
        struct stat fSize;
        stat(fileName, &fSize);
        return fSize.st_size;
}

/*
 The Cryptographic Coat manages everything outside the encryption process, such as file handling, providing an interface to the
 available modes of operation.
 The task of any encryption* decryption* function is to perform cryptographic operations on its parameters, anything else is taken care of by the motor.
 */

void cryptographicCoat(){

        uint8_t padding = 0;
        uint8_t *buffer;
        int functionality;
        int modeOfOperation;
        FILE* fileReader;
        FILE* keyReader;
        uint8_t key[BLOCK_SIZE];
        char outputName[20];
        char filePath[30];
        char keyPath[30];
        long fileSize;
    
        printf("\nSelect functionality\n1 - Encryption\n2 - Decryption\n");
        scanf("%d", &functionality);
        
        if(functionality != 1 && functionality != 2)
                return;
            
        if(!(fileReader = searchForFilePlus(filePath, "plaintext")) || // check if files exist
           !(keyReader = searchForFilePlus(keyPath, "key "))){
                printf("\nFile does not exist or could not be opened");
                return;
        }
        
        fread(key, 1, KEY_SIZE, keyReader);
        fclose(keyReader);
        fileSize = getFileSize(filePath);
    
        if(((modeOfOperation == OFB || CCM )&& functionality == 1))  //Checks the mode of operation in order to determine whether or not to write/read the IV of the file
                    fileSize+=BLOCK_SIZE;
        
        buffer = (uint8_t*)malloc((fileSize+padding)*sizeof(uint8_t));
        
        if(buffer == NULL){
                printf("Insufficient memory");
                return;
        }
        
        if(fileSize % BLOCK_SIZE != 0){
                padding = (fileSize/BLOCK_SIZE+1)*BLOCK_SIZE - fileSize;
                for(long i = fileSize;i<fileSize+padding;i++)   // padding last block with white spaces
                        buffer[i] = 32;
        }

        fread(buffer, 1, fileSize, fileReader);
        fclose(fileReader);

    encryptionCTR(buffer, key, fileSize+padding);
    
    printf("Ciphertext: %s",buffer);
    free(buffer);
}
    int main () {
       cryptographicCoat();
   }

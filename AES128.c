//
//  AES128.c
//  AES
//
//
#include "AES128.h"
#include <stdint.h>

// This file contains the raw implementation of AES, without any auxiliary
// functionality or data.

#define BLOCK_SIZE 16 // 128 bit blocks
#define KEY_SIZE 16   // 128 bit-long key

uint8_t expandedKey[10][KEY_SIZE];

uint8_t rcon[10][4] = // rcon or round const values are different for each round
    {0x01, 0, 0, 0, 0x02, 0, 0, 0, 0x04, 0, 0, 0, 0x08, 0, 0, 0, 0x10, 0, 0, 0,
     0x20, 0, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0, 0x1b, 0, 0, 0, 0x36, 0, 0, 0};

/* **************************SUB_BYTES********************************** */
/*Each byte in the nonce+counter is substituted using the sbox
 *S boxes for every byte is identical
 *Sbox is calculated by finding inverse over GF 2^8 and affine mapping
 */

inline void subBytes(uint8_t *state) {
  for (int i = 0; i < 4; i++) {
    state[i * 4] = sBox[state[i * 4]];
    state[i * 4 + 1] = sBox[state[i * 4 + 1]];
    state[i * 4 + 2] = sBox[state[i * 4 + 2]];
    state[i * 4 + 3] = sBox[state[i * 4 + 3]];
  }
}

/* **************************INVERSE_SUB_BYTES**********************************
 */
/*Inverse subbytes is used for decryption
 * Seperate table exists
 */

inline void invSubBytes(uint8_t *state) {
  for (int i = 0; i < 4; i++) {
    state[i * 4] = inv_sBox[state[i * 4]];
    state[i * 4 + 1] = inv_sBox[state[i * 4 + 1]];
    state[i * 4 + 2] = inv_sBox[state[i * 4 + 2]];
    state[i * 4 + 3] = inv_sBox[state[i * 4 + 3]];
  }
}

/* **************************SHIFT_ROWS********************************** */
/*Consider the state as a 4x4 matrix
 *Each row is left shifted by (n-1) where n is row number
 *Here we've used swapping and substitution to emulate the same
 */
inline void
shiftRows(uint8_t *state) { // Looks like crap but it's faster than a crab
  uint8_t swap;
  swap = state[4];
  state[4] = state[5];
  state[5] = state[6];
  state[6] = state[7];
  state[7] = swap;
  swap = state[15];
  state[15] = state[14];
  state[14] = state[13];
  state[13] = state[12];
  state[12] = swap;
  (void)(state[8] ^= state[10]), (void)(state[10] ^= state[8]),
      state[8] ^= state[10];
  (void)(state[9] ^= state[11]), (void)(state[11] ^= state[9]),
      state[9] ^= state[11];
}

/* **************************INVERSE_SHIFT_ROWS**********************************
 */
/*Similar to Shift row
 * Used in decryption
 */

inline void invShiftRows(uint8_t *state) {
  uint8_t swap;
  swap = state[7];
  state[7] = state[6];
  state[6] = state[5];
  state[5] = state[4];
  state[4] = swap;
  swap = state[12];
  state[12] = state[13];
  state[13] = state[14];
  state[14] = state[15];
  state[15] = swap;
  (void)(state[8] ^= state[10]), (void)(state[10] ^= state[8]),
      state[8] ^= state[10];
  (void)(state[9] ^= state[11]), (void)(state[11] ^= state[9]),
      state[9] ^= state[11];
}

/* **************************MIX_COLUMNS********************************** */
/*Take the output of Shift Rows
 *Each row is multiplied with a fixed matrix
 *Multiplication is polynomial under GF 2^8
 *AES MOD=X^8+X^4+X^3+X+1
 *The resultant of multiplication is stored as mul2,mul3 in Lookuptables
 *Addition in GF is equivalent to xoring
 */

inline void mixColumns(uint8_t *state) {
  uint8_t s[4];
  for (int i = 0; i < 4; i++) {
    s[0] = (mul2[state[i]] ^ mul3[state[i + 4]] ^ state[i + 8] ^ state[i + 12]);
    s[1] = (state[i] ^ mul2[state[i + 4]] ^ mul3[state[i + 8]] ^ state[i + 12]);
    s[2] = (state[i] ^ state[i + 4] ^ mul2[state[i + 8]] ^ mul3[state[i + 12]]);
    s[3] = (mul3[state[i]] ^ state[i + 4] ^ state[i + 8] ^ mul2[state[i + 12]]);
    state[i] = s[0];
    state[i + 4] = s[1];
    state[i + 8] = s[2];
    state[i + 12] = s[3];
  }
}
/* **************************INVERSE_MIX_COLUMNS**********************************
 */
/*Similar to mix columns
 *Used in decryption
 */

inline void invMixColumns(uint8_t *state) {
  uint8_t s[4];
  for (int i = 0; i < 4; i++) {
    s[0] = mul_14[state[i]] ^ mul_11[state[i + 4]] ^ mul_13[state[i + 8]] ^
           mul_9[state[i + 12]];
    s[1] = mul_9[state[i]] ^ mul_14[state[i + 4]] ^ mul_11[state[i + 8]] ^
           mul_13[state[i + 12]];
    s[2] = mul_13[state[i]] ^ mul_9[state[i + 4]] ^ mul_14[state[i + 8]] ^
           mul_11[state[i + 12]];
    s[3] = mul_11[state[i]] ^ mul_13[state[i + 4]] ^ mul_9[state[i + 8]] ^
           mul_14[state[i + 12]];
    state[i] = s[0];
    state[i + 4] = s[1];
    state[i + 8] = s[2];
    state[i + 12] = s[3];
  }
}

/* **************************ADD_ROUND_KEY********************************** */
// This stage is just xoring the state with the roundkey

inline void addRoundKey(uint8_t *state, uint8_t *roundKey) {
  for (int i = 0; i < 4; i++) {
    state[i * 4] ^= roundKey[i * 4];
    state[i * 4 + 1] ^= roundKey[i * 4 + 1];
    state[i * 4 + 2] ^= roundKey[i * 4 + 2];
    state[i * 4 + 3] ^= roundKey[i * 4 + 3];
  }
}

/* **************************KEY_SCHEDULING********************************** */
// This is the part where we take the initial 16 byte key and make it long
// enough for 10 rounds of AES

void keySchedule(uint8_t *key, int round) {
  uint8_t first = key[3];
  uint8_t arr[4] = {key[3], key[7], key[11],
                    key[15]}; // Making an array of all the key elements coming
                              // in the last col
  for (int i = 0; i < 3; i++) {
    arr[i] = sBox[arr[i + 1]]; // Circular shift + sbox substitution in aline
  }
  arr[3] = sBox[first];
  for (int i = 0; i < 4; i++) {
    key[i * 4] =
        key[i * 4] ^ arr[i] ^
        rcon[round][i]; // Preparing the elements that are multiples of 4
  }
  for (int i = 1; i < 4; i++) {
    key[i] = key[i] ^ key[i - 1];
    key[i + 4] = key[i + 4] ^ key[i + 3]; // Preparing the rest of the elements
    key[i + 8] = key[i + 8] ^ key[i + 7];
    key[i + 12] = key[i + 12] ^ key[i + 11];
  }
}

void keyExpansion(uint8_t *key) {
  uint8_t k[KEY_SIZE];
  for (int i = 0; i < 16; i++) {
    k[i] = key[i];
  }
  for (int i = 0; i < 10; i++) { // Calls the key schedule function for each
                                 // round basically helps selecting rcon values
    keySchedule(k, i);
    for (int j = 0; j < 16; j++) {
      expandedKey[i][j] = k[j];
    }
  }
}

/* **************************ENCRYPT_BLOCK********************************** */
/*The main function in encryption
 * Calls all of the steps in order:
      1.SubBytes
      2.ShiftRows
      3.MixColumns
      4.AddRoundkey
 * Final round avoids mix columns
*/

void encryptBlock(uint8_t *state, uint8_t *encryption_key) {
  addRoundKey(state, encryption_key);
  for (int i = 0; i < 9; i++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, &expandedKey[i]);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, &expandedKey[9]);
}

/* **************************DECRYPT_BLOCK********************************** */
/*The main function in decryption
 *Calls all of the steps in order:
      1.InvShiftRows
      2.InvSubBytes
      3.AddRoundkey
      4.InvMixColumns
*Final round excludes InvMixColumns
*/
void decryptBlock(uint8_t *state, uint8_t *encryption_key) {
  addRoundKey(state, &expandedKey[9]);
  for (int i = 8; i >= 0; i--) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, &expandedKey[i]);
    invMixColumns(state);
  }
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, encryption_key);
}

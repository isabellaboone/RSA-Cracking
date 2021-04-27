/* ***********************************************
* Author: T. Briggs (c) 2019
* Date: 2019-02-25
* 
* Brute-force attach against an RSA key.
*
* Reads the public key files and iterates through
* all of the odd numbers from 3 to 2^key_len
************************************************ */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// GNU Multi-Precision Math
// apt-get install libgmp-dev, gcc ... -lgmp
#include <gmp.h>

// My RSA library - don't use for NSA work
#include "rsa.h"

// Print a block of bytes as hexadecimal
void print_buff(int len, char *buf)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x", (unsigned char) buf[i]);
	}
}

// Set the expected key length (in bits)
#define KEY_LEN 32

// Set the maximum number of characters 
// in a message (in bytes)
#define BLOCK_LEN 32

int main(int argc, char **argv)
{

	rsa_keys_t keys;						// the RSA keys
	
	// a block of text for the encrypted and decrypted messages
	// it has to be large enough to handle the padding we might
	// get back from the encrypted/decrypted functions
	char *encrypted = malloc(1024*2);
	char *decrypted = malloc(1024*2);

	// read the public keys from the file
	printf("Reading Alice's public keys\n");
	char *fname = malloc(1024);
	sprintf(fname,"public-%d.txt", KEY_LEN);
	rsa_read_public_keys(&keys, fname);
	
	printf("Reading encrypted message\n");
	sprintf(fname,"encrypted-%d.dat", KEY_LEN);
	FILE *fp = fopen(fname,"r+");
	if (fp == NULL) {
		perror("could not open encrypted text");
		exit(-1);
	}
	
	int bytes = fread(encrypted, 1, BLOCK_LEN*(KEY_LEN/8), fp);
	printf("Read %d bytes\n", bytes);
	fclose(fp);

	// Initialize the RSA key (candidate private key)
	mpz_init(keys.d);
	
	unsigned long i;
	unsigned long end = (1L << KEY_LEN) - 3;
	int count = 0;
	
	for (i = 3; i < end; i+=2) {
	
		// print some progress out to the screen
		if (count++ == 50000) {
			printf("\r%lx/%lx %0.1f%%", i, end, ((double)i/(double)end)*100.0);
			fflush(stdout);
			count = 0;
		}
		
		// set the private key to try 
		mpz_set_ui(keys.d, i);
		
		// decrypt the message using our current guess
		rsa_decrypt(encrypted, decrypted, bytes, &keys);
		
		// check to see if it starts with "<h1>"
		if (!strncmp(decrypted,"<h1>",4)) {	
				printf("Found key: %lu %lx\n", i, i);
				printf("Message: %s\n", decrypted);
				
				// this may actually be garbage.  so, don't quit.
				// break
			}
	}
	if(i >= end) {
		printf("did not find key\n");
	}

	// free up the memory we gobbled up
	free(encrypted);
	free(decrypted);
	free(fname);
	
	mpz_clear(keys.d);
	mpz_clear(keys.n);
	mpz_clear(keys.e);
	mpz_clear(keys.p);
	mpz_clear(keys.q);
}

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
#include <pthread.h>

// GNU Multi-Precision Math
// apt-get install libgmp-dev, gcc ... -lgmp
#include <gmp.h>

// My RSA library - don't use for NSA work
#include "rsa.h"

#define NUM_THREADS 20

//Struct for a single key
typedef struct { 
	int bytes;
	rsa_keys_t keys;
	char* encrypted;
	char* decrypted;
	long start_row;
    long end_row;
	int* found;
	//pthread_mutex_t lock;
} rsa_decrypt_t;


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


void *thread_func(void *thread_input){
	rsa_decrypt_t *tread_struct = (rsa_decrypt_t *)thread_input;
	int count = 0;
	*(tread_struct->found) = 0;

	while(tread_struct->start_row < tread_struct->end_row) {
		//&& *tread_struct->found != 1
		if(*tread_struct->found == 1) {
			printf("Exiting because it was found!\n");
			break;
		}
		// print some progress out to the screen
		// if (count++ == 50000) {
			
		// 	printf("\r%lx/%lx %0.1f%%\n", i, poop_args->end_row, ((double)i/(double)poop_args->end_row)*100.0);
		// 	//fflush(stdout);
		// 	count = 0;
		// }
		
		// set the private key to try 
		mpz_set_ui(tread_struct->keys.d, tread_struct->start_row);
		
		// decrypt the message using our current guess
		rsa_decrypt(tread_struct->encrypted, tread_struct->decrypted, tread_struct->bytes, &tread_struct->keys);

		// check to see if it starts with "<h1>"
		if (!strncmp(tread_struct->decrypted,"<h1>",4)) {	
			//printf("LOCKING THREAD %ld\n", tread_struct->end_row);
			//pthread_mutex_lock(&tread_struct->lock);
				*(tread_struct->found) = 1;
				printf("Found key: %ld %ld\n", tread_struct->start_row, tread_struct->start_row);
				printf("Message: %s\n", tread_struct->decrypted);
				fflush(stdout);
				// this may actually be garbage.  so, don't quit.
				// break
			//pthread_mutex_unlock(&tread_struct->lock);
			//printf("UNLOCKING %ld\n", tread_struct->end_row);
		}

		tread_struct->start_row+=2; 
	}

	printf("I FINISHED %ld\n", tread_struct->end_row);

}


int main(int argc, char **argv)
{

	rsa_keys_t keys;					// the RSA keys
	int *found = calloc(10, sizeof(int));
	
	// a block of text for the encrypted and decrypted messages
	// it has to be large enough to handle the padding we might
	// get back from the encrypted/decrypted functions
	char *encrypted = malloc(1024*2);
	// char *decrypted = malloc(1024*2);

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

	
	
	unsigned long i;
	unsigned long end = (1L << KEY_LEN) - 3;
	int count = 0;
	
	pthread_t thread_ids[NUM_THREADS];
	rsa_decrypt_t concurrent_keys[NUM_THREADS];
	//pthread_mutex_t lock;
	//pthread_mutex_init(&lock, NULL);

	for(int i=0; i<NUM_THREADS; i++){
		concurrent_keys[i].start_row = i * (end/NUM_THREADS);
		concurrent_keys[i].end_row = concurrent_keys[i].start_row + (end/NUM_THREADS);
		
		if (concurrent_keys[i].start_row == 0){
			concurrent_keys[i].start_row = 3;
			//concurrent_keys[i].end_row = concurrent_keys[i].start_row + (end/NUM_THREADS);
		}

		

		printf("START: %ld\n", concurrent_keys[i].start_row);
		printf("END: %ld\n", concurrent_keys[i].end_row);
		
		// Initialize the RSA key (candidate private key)
		mpz_init(keys.d);

		concurrent_keys[i].keys = keys;
		concurrent_keys[i].bytes = bytes;
		concurrent_keys[i].encrypted = encrypted;
		concurrent_keys[i].decrypted = malloc(1024*2);
		concurrent_keys[i].found = found;
		//concurrent_keys[i].lock = lock;
	}

	for(int i=0; i<NUM_THREADS; i++){
    pthread_create(&thread_ids[i], NULL, thread_func, &concurrent_keys[i]);
  }

  for(int i=0; i<NUM_THREADS; i++){
    pthread_join(thread_ids[i], NULL);
  }

	// free up the memory we gobbled up
	free(encrypted);
	// free(decrypted);
	free(fname);
	
	mpz_clear(keys.d);
	mpz_clear(keys.n);
	mpz_clear(keys.e);
	mpz_clear(keys.p);
	mpz_clear(keys.q);
}

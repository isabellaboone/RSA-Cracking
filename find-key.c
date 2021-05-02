/* ***********************************************
* Author: T. Briggs (c) 2019
* Date: 2019-02-25
* 
* Brute-force attach against an RSA key.
*
* Reads the public key files and iterates through
* all of the odd numbers from 3 to 2^key_len
************************************************ */ 

#include <stdio.h> // input/output
#include <stdlib.h> // sizes, malloc, etc
#include <string.h> // String functions 
#include <ctype.h> // More types
#include <pthread.h> // Threading 
#include <time.h> // For time functions
#include <stdint.h> // For uint64

// GNU Multi-Precision Math
// apt-get install libgmp-dev, gcc ... -lgmp
#include <gmp.h>

// My RSA library - don't use for NSA work
#include "rsa.h"
#include "primefact.h"

#define NUM_THREADS 16 // Number of threads
#define BLOCK_LEN 32 // Max num of chars in message (in bytes)

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

/**
 * @brief Start the timer. 
 * 
 * @return struct timespec 
 */
struct timespec timer_start() {
  struct timespec tick;
  clock_gettime(CLOCK_MONOTONIC, &tick); // Get current time
  return tick;  
}

/**
 * @brief End the timer. Return how long the timer went for. 
 * 
 * @param tick struct timesspec of when timer was started. 
 * @return uint64_t Unsigned int of total time in ns. 
 */
uint64_t timer_end(struct timespec tick) {
  struct timespec tock;
  clock_gettime(CLOCK_MONOTONIC, &tock); 
  uint64_t start_nanos = tick.tv_sec * (long) 1e9 + tick.tv_nsec;
  uint64_t end_nanos = tock.tv_sec * (long) 1e9 + tock.tv_nsec;

  return (end_nanos - start_nanos) / 1000; 
}

// Print a block of bytes as hexadecimal
void print_buff(int len, char *buf)
{
	for (int i = 0; i < len; i++) {
		printf("%02x", (unsigned char) buf[i]);
	}
}

/**
 * @brief Method each thread follows upon launch. 
 * 
 * @param thread_input 
 * @return void* 
 */
void *thread_func(void *thread_input){
	rsa_decrypt_t *thread_struct = (rsa_decrypt_t *)thread_input;
	int count = 0;
	*(thread_struct->found) = 0;

	while(thread_struct->start_row < thread_struct->end_row) {
		//&& *thread_struct->found != 1
		if(*thread_struct->found == 1) {
			// printf("Exiting because it was found!\n");
			break;
		}
		// print some progress out to the screen
		// if (count++ == 50000) {
			
		// 	printf("\r%lx/%lx %0.1f%%\n", i, poop_args->end_row, ((double)i/(double)poop_args->end_row)*100.0);
		// 	//fflush(stdout);
		// 	count = 0;
		// }
		
		// set the private key to try 
		mpz_set_ui(thread_struct->keys.d, thread_struct->start_row);
		
		// decrypt the message using our current guess
		rsa_decrypt(thread_struct->encrypted, thread_struct->decrypted, thread_struct->bytes, &thread_struct->keys);

		// check to see if it starts with "<h1>"
		if (!strncmp(thread_struct->decrypted,"<h1>",4)) {	
			//printf("LOCKING THREAD %ld\n", thread_struct->end_row);
			//pthread_mutex_lock(&thread_struct->lock);
				*(thread_struct->found) = 1;
				printf("Found key: %ld %ld\n", thread_struct->start_row, thread_struct->start_row);
				printf("Message: %s\n", thread_struct->decrypted);
				fflush(stdout);
				// this may actually be garbage.  so, don't quit.
				// break
			//pthread_mutex_unlock(&thread_struct->lock);
			//printf("UNLOCKING %ld\n", thread_struct->end_row);
		}

		thread_struct->start_row+=2; 
	}

	// printf("I FINISHED %ld\n", thread_struct->end_row);

}


int main(int argc, char **argv)
{
	int flag = 1; 

	while(flag) { 
		struct timespec t = timer_start();
		int keysize; 
		rsa_keys_t keys; // the RSA keys
		int *found = calloc(10, sizeof(int)); 

		// a block of text for the encrypted and decrypted messages
		// it has to be large enough to handle the padding we might
		// get back from the encrypted/decrypted functions
		char *encrypted = malloc(1024*2);
		char *decrypted = malloc(1024*2);

		printf("Enter key size: "); 
		scanf("%d", &keysize); // scanf bad but i'm lazy, change this to fgets later
		
		printf("%d\n", keysize);

		if(keysize == 0) { 
			flag = 0;
		}

		// Read public keys from file 
		char *fname = malloc(1024);
		sprintf(fname,"public-%d.txt", keysize);
		rsa_read_public_keys(&keys, fname);

		printf("Reading encrypted message\n");
		sprintf(fname,"encrypted-%d.dat", keysize);
		FILE *fp = fopen(fname,"r+");

		if (fp == NULL) {
		perror("could not open encrypted text");
		exit(-1);
		}
		
		int bytes = fread(encrypted, 1, BLOCK_LEN*(keysize/8), fp);
		printf("Read %d bytes\n", bytes);
		fclose(fp);

		unsigned long i;
		unsigned long end = (1L << keysize) - 3;
		int count = 0;

		uint64_t p = pollardRho(mpz_get_ui(keys.n)); 
		uint64_t q = mpz_get_ui(keys.n) / p; 

		uint64_t phi_n = (p - 1) * (q - 1); 

		mpz_t result, phi_n_2; 
		mpz_init(result); 
		mpz_init(phi_n_2);
		mpz_set_ui(phi_n_2, phi_n);
		mpz_invert(keys.d, keys.e, phi_n_2);

		rsa_decrypt(encrypted, decrypted, bytes, &keys);
		printf("Message: %s\n", decrypted);
		// free up the memory we gobbled up
		free(encrypted);
		free(decrypted);
		free(fname);
	
		mpz_clear(keys.d);
		mpz_clear(keys.n);
		mpz_clear(keys.e);
		mpz_clear(keys.p);
		mpz_clear(keys.q);

		printf("Took %lu usecs\n", timer_end(t)); 
	}
	printf("Exiting\n");
}

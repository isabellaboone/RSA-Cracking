/* ***********************************************
* Author: T. Briggs (c) 2019
* Date: 2019-02-25
* 
* Brute-force attach against an RSA key.
*
* Reads the public key files and iterates through
* all of the odd numbers from 3 to 2^key_len
************************************************ */

#include <stdio.h>	 // input/output
#include <stdlib.h>	 // sizes, malloc, etc
#include <string.h>	 // String functions
#include <ctype.h>	 // More types
#include <pthread.h> // Threading
#include <time.h>		 // For time functions
#include <stdint.h>	 // For uint64

// GNU Multi-Precision Math
// apt-get install libgmp-dev, gcc ... -lgmp
#include <gmp.h>

// My RSA library - don't use for NSA work
#include "rsa.h"
#include "primefact.h"

#define NUM_THREADS 1 // Number of threads
#define BLOCK_LEN 32	 // Max num of chars in message (in bytes)

/**
 * @brief Start the timer. 
 * 
 * @return struct timespec of currect time.
 */
struct timespec timer_start()
{
	struct timespec tick;
	clock_gettime(CLOCK_MONOTONIC, &tick); // Get current time
	return tick;
}

/**
 * @brief End the timer. Return how long the timer went for. 
 * 
 * @param tick struct timesspec of when timer was started. 
 * @return uint64_t Unsigned int of total time in us. 
 */
uint64_t timer_end(struct timespec tick)
{
	struct timespec tock;
	clock_gettime(CLOCK_MONOTONIC, &tock);
	uint64_t start_nanos = tick.tv_sec * (long)1e9 + tick.tv_nsec;
	uint64_t end_nanos = tock.tv_sec * (long)1e9 + tock.tv_nsec;

	return (end_nanos - start_nanos) / 1000;
}

// Print a block of bytes as hexadecimal
void print_buff(int len, char *buf)
{
	for (int i = 0; i < len; i++)
	{
		printf("%02x", (unsigned char)buf[i]);
	}
}

/**
 * @brief Method each thread follows upon launch. 
 * 
 * @param thread_input rsa_decrypt_t struct containing 
 *   information necessary to crack stuff. 
 */
void *thread_func(void *thread_input) {
  // Create constant as mpz_t
	mpz_t ONE; 
	mpz_init(ONE); 
	mpz_set_ui(ONE, 1); 

	rsa_decrypt_t *thread_struct = (rsa_decrypt_t *)thread_input;

  // Create & initialize p
	mpz_t p; 
	mpz_init(p); 
	mpz_init(thread_struct->p);
  // Call pollardrho to find p value
	pollardRho(thread_struct->keys->n, thread_struct);

  // Check if any other thread has already finished the prime factorization first. 
	if (*thread_struct->found == 1) {
		printf("Exiting because it was found!\n");
	}
  
	mpz_set(p, thread_struct->p); // copy p over

  // Create, initialize and calculate q (n/p = q)
	mpz_t q; 
	mpz_init(q);
	mpz_div(q, thread_struct->keys->n, p); 

  // Create and initialize phi_n
	mpz_t phi_n;
	mpz_init(phi_n);
  
  // Subtract 1 from p and q
	mpz_sub(p, p, ONE); 
	mpz_sub(q, q, ONE); 

  // Calculate phi_n = (p-1) * (q-1)
	mpz_mul(phi_n, p, q); 

  // Initialize keys->d, and calculate d
	mpz_init(thread_struct->keys->d);
	mpz_invert(thread_struct->keys->d, thread_struct->keys->e, phi_n);
}

int main(int argc, char **argv) {
	int flag = 1;

	while (flag) {
		int keysize; // user input, key to run
		rsa_keys_t keys; // the RSA keys
		int *found = calloc(10, sizeof(int));
		char *encrypted = malloc(1024 * 2);
		char *decrypted = malloc(1024 * 2);

		printf("Enter key size: ");
		scanf("%d", &keysize); // scanf bad but i'm lazy, change this to fgets later

		// Read public keys from file
		char *fname = malloc(1024);
		sprintf(fname, "keys/public-%d.txt", keysize);
		rsa_read_public_keys(&keys, fname);

		printf("Reading encrypted message\n");
		sprintf(fname, "keys/encrypted-%d.dat", keysize);
		FILE *fp = fopen(fname, "r+");

		if (fp == NULL) {
			perror("could not open encrypted text");
			exit(-1);
		}

		int bytes = fread(encrypted, 1, BLOCK_LEN * (keysize / 8), fp);
		printf("Read %d bytes\n", bytes);
		fclose(fp);

		struct timespec t = timer_start(); // Start timer

		pthread_t thread_ids[NUM_THREADS];
		rsa_decrypt_t concurrent_keys[NUM_THREADS];

		// Initialize concurrent_keys[i]
		for (int i = 0; i < NUM_THREADS; i++) {
			concurrent_keys[i].keys = &keys;
			concurrent_keys[i].found = found;
		}

		// Launch threads
		for (int i = 0; i < NUM_THREADS; i++) {
			pthread_create(&thread_ids[i], NULL, thread_func, &concurrent_keys[i]);
		}

		// Rejoin threads
		for (int i = 0; i < NUM_THREADS; i++)	{
			pthread_join(thread_ids[i], NULL);
		}

		// Decrypt 
		rsa_decrypt(encrypted, decrypted, bytes, &keys);
		printf("Message: %s\n", decrypted);

		uint64_t endtimer = timer_end(t);
		printf("Took %lu usecs\n", endtimer);

		// Free up the memory we gobbled up
		free(encrypted);
		free(decrypted);
		free(fname);
		free(found);
		mpz_clear(keys.d);
		mpz_clear(keys.n);
		mpz_clear(keys.e);
		mpz_clear(keys.p);
		mpz_clear(keys.q);

	}
}

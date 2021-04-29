#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include <string.h>
#include <assert.h>

#include "rsa.h"

#define IO_BYTE_ORDER 0
#define IO_ENDIANNESS 0

#define BYTES_TO_MPZ(mpz, ptr, len) {\
	mpz_import(mpz, len, IO_BYTE_ORDER, 1, IO_ENDIANNESS, 0, ptr);  \
	}

#define MPZ_TO_BLOCK(mpz, ptr, block_size ) ({\
	size_t _count; 	mpz_export((char *)ptr, &_count, IO_BYTE_ORDER, block_size, IO_ENDIANNESS, 0, mpz); _count * block_size;  \
	})

#define BLOCK_TO_MPZ(mpz, ptr, block_size) {\
	mpz_import(mpz, 1, IO_BYTE_ORDER, block_size, IO_ENDIANNESS, 0, ptr);  \
	}


static void compute_totient(mpz_t lambda, const mpz_t p, const mpz_t q);
static void compute_keys(rsa_keys_t *keys, const mpz_t lambda);
static int compute_enc_block_size(int desired_key_size);
static int compute_dec_block_size(int desired_key_size);

static void print_key(const char *str, const mpz_t key);
static void print_raw(const char *str, int len, const char *raw);

#ifdef linux
static void rsa_init_from_devrandom(gmp_randstate_t state);
#endif

void rsa_testkeys(rsa_keys_t *keys)
{
	mpz_inits(keys->p, keys->q, keys->n, 
		keys->d, keys->e, NULL);
		
	mpz_t lambda;
	mpz_inits(lambda, NULL);

	// step1 - initialize p & q, two prime numbers
	mpz_set_ui(keys->p, 1009);
	mpz_set_ui(keys->q, 1013);

	keys->num_bits = 32;
	keys->enc_block_size = compute_enc_block_size(32);
	keys->dec_block_size = compute_dec_block_size(32);
	
	assert(mpz_probab_prime_p(keys->p, 25) > 0);
	assert(mpz_probab_prime_p(keys->q, 25) > 0);
	
	// Compute n = pq.
	mpz_mul(keys->n, keys->p, keys->q);

	// step 3 - compute Carmichael's totient
	compute_totient(lambda, keys->p, keys->q);

	// step 4 & 5 - compute d & e
	compute_keys(keys, lambda);
	
#ifdef DEBUG
	printf("******* RSA TEST KEYS **************\n");
	print_key("p: ", keys->p);
	print_key("q: ", keys->q);
	print_key("n: ", keys->n);
	print_key("l: ", lambda);
	print_key("d: ", keys->d);
	print_key("e: ", keys->e);
#endif
	
	mpz_clears(lambda, NULL);
}

/* generate_keys - generate RSA keys, public and private
  From: https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
  RSA algorithm key generation algorithm:
  # choose two prime numbers, p and q.  The can be quite large
  # compute the modulues for keys $n = p q$ 
  # use compute_lambda & compute_keys to finish the process
  
*/
void rsa_genkeys(unsigned int num_bits, rsa_keys_t *keys)
{
	mpz_inits(keys->p, keys->q, keys->n, 
	keys->d, keys->e, NULL);
		
	mpz_t lambda;
	mpz_inits(lambda, NULL);

	// initialize the GMP random number generator 
	// using the Mersenne Twister algorithm
	gmp_randstate_t state;
	gmp_randinit_mt(state); 

	// use gcc -dM -E - < /dev/null to get standard defines
#ifndef linux
	gmp_randseed_ui(state, clock());
#else
	rsa_init_from_devrandom(state);
#endif

	// pick a random number for p, make sure its prime
	mpz_urandomb(keys->p, state, num_bits / 2);
	mpz_nextprime(keys->p, keys->p);
	
	// pick a random number of q, make sure its prime
	int num_p_bits = mpz_sizeinbase(keys->p, 2);
	mpz_urandomb(keys->q, state, num_bits - num_p_bits);
	mpz_nextprime(keys->q, keys->q);
	
	// compute n = p * q
	mpz_mul(keys->n, keys->p, keys->q);

	// determine the block sizes based on these numbers
	// we can only encode a chunk whose value is smaller than n,
	// so we will break-up a long message by this size.
	keys->num_bits = mpz_sizeinbase(keys->n, 2);
	keys->enc_block_size = compute_enc_block_size(num_bits);
	keys->dec_block_size = compute_dec_block_size(num_bits);
	
	//assert( mpz_sizeinbase(keys->n, 256) > keys->enc_block_size);
	//assert( mpz_sizeinbase(keys->n, 256) <= keys->dec_block_size);
	
	// step 3 - compute Carmichael's totient
	compute_totient(lambda, keys->p, keys->q);

	// step 4 & 5 - compute d & e
	compute_keys(keys, lambda);
	
#ifdef DEBUG
	printf("******* RSA TEST KEYS **************\n");
	printf("key size: %u / %u %u\n", 
		keys->num_bits, keys->enc_block_size, keys->dec_block_size);
	print_key("p: ", keys->p);
	print_key("q: ", keys->q);
	print_key("n: ", keys->n);
	print_key("l: ", lambda);
	print_key("d: ", keys->d);
	print_key("e: ", keys->e);
#endif
	
	mpz_clears(lambda, NULL);
}


// Encrypt a block of data using the given e and n (private keys).
// the block_size is the number of bytes in the clear message, and the
// out_block_size is the number of bytes in a chunk in the encrypted msg.
static size_t rsa_encrypt_block(const mpz_t e, const mpz_t n, int in_block_size, 
	int out_block_size, const char const *clear, char *encrypted)
{
	int i;
	mpz_t m, c;
	mpz_inits(m, c, NULL);

	// create m from block data
	BLOCK_TO_MPZ(m, clear, in_block_size);
	
	mpz_powm(c, m, e, n);

	size_t count = MPZ_TO_BLOCK(c, encrypted, out_block_size);

#ifdef DEBUG
	printf("** Encrypt Block **\n");
	printf("resulting block: %lu block size: %u\n", 
		mpz_sizeinbase(c, 256), out_block_size);
		
	print_raw("clear: ", in_block_size, clear);	
	print_key("m", m); print_key("e", e); print_key("n", n);
	print_key("c", c);		
	print_raw("encry: ", out_block_size, encrypted);	
	printf("\n");	
#endif

	mpz_clears(m,c, NULL);
	return out_block_size;
}


// Decrypt a block of data using the given d and n (public keys).
// the block_size is the number of bytes in the clear message, and the
// out_block_size is the number of bytes in a chunk in the encrypted msg.

static size_t rsa_decrypt_block(const mpz_t d, const mpz_t n, 
	int in_block_size, int out_block_size, const char const *encrypted, char *clear)
{
	mpz_t m, c;
	
	mpz_inits(m, c, NULL);
	
	// convert a block of bytes into an mpz_t (big integer)
	BLOCK_TO_MPZ(c, encrypted, in_block_size);
	
	// compute the modular exponentiation 
	mpz_powm(m, c, d, n);
	
	// converft the mpz back to a block of bytes
	size_t count = MPZ_TO_BLOCK(m, clear, out_block_size);
	
#ifdef DEBUG	
	 printf("\n******* Decrypt Block ******\n");
	 print_raw("encry: ", in_block_size, encrypted);	
	 print_key("c", c); print_key("d", d); print_key("n", n); 
	 print_key("m", m);
	 print_raw("clear: ", out_block_size, clear);
	 printf("\n");
#endif

	mpz_clears(m, c, NULL);

	return out_block_size;
}




// Encrypt a message using the private keys.  The input message is encrypted
// into the output buffer (encrypted).  The length of the message is stored
// in the message_bytes.  The length of the encrypted message is returned.
size_t rsa_encrypt(char *message, char *encrypted, int message_bytes, 
	rsa_keys_t *keys)
{
	size_t encrypted_bytes = 0;

#ifdef DEBUG
	printf("\n*******************************************\n");
	print_raw("Message to encrypt: ",message_bytes, message);
	printf("Sender's private key: ");
	print_key("n:", keys->n);
	print_key("e:", keys->e);
#endif

	// grab bytes to encrypt
	int in_block_size = keys->enc_block_size;
	int out_block_size = keys->dec_block_size;
	
	// a chunk to encrypt
	char *curr_block = calloc(in_block_size, 1);
	
	// for each chunk of the message, encrypt it and go to the next chunk
	int curr_byte = 0;
	while (curr_byte < message_bytes) {
		
		// force un-filled block to be 0 padded
		memset(curr_block, 0, in_block_size);
		
		// figure out what type of chunk this is
		int remaining_bytes = message_bytes - curr_byte;
		if (remaining_bytes < in_block_size) {
#ifdef DEBUG
			printf("   >> small block (%d < %d) << \n", remaining_bytes, in_block_size);
#endif
			memcpy(curr_block, message+curr_byte, remaining_bytes);
		}
		else {
#ifdef DEBUG
			printf("  >> full block logic (%d) << \n", in_block_size);
#endif
			memcpy(curr_block, message+curr_byte, in_block_size);
		}
		
		// actually encrypt the chunk
		int enc_bytes = rsa_encrypt_block(keys->e, keys->n, 
			in_block_size, out_block_size, 
			curr_block,
			&encrypted[encrypted_bytes]);

#ifdef DEBUG
		print_raw("Encrypted block:", enc_bytes, &encrypted[encrypted_bytes]);
#endif

		// update the indices for input and output chunks
		curr_byte += in_block_size;
		encrypted_bytes += enc_bytes;
	}

#ifdef DEBUG
	print_raw("Encrypted message: ", encrypted_bytes, encrypted);
#endif
	return encrypted_bytes;
}



/* decrypt a message  The encrypted message is passed in on the "message" pointer.
The length of the encrypted message (number of bytes) is stored in message_bytes.  The 
private keys (d and n) are used from the keys.  The number of decrypted bytes is returned. */
size_t rsa_decrypt(char *message, char *decrypted, int message_bytes, 
	rsa_keys_t *keys)
{
	size_t decrypted_bytes = 0;
	
#ifdef DEBUG
	printf("\n*******************************************\n");
	print_raw("Message to decrypt: ",message_bytes, message);
	printf("Sender's public key: ");
	print_key("n:", keys->n);
	print_key("d:", keys->d);
#endif

	// compute the block sizes that will be processed
	int in_block_size = keys->dec_block_size;
	int out_block_size = keys->enc_block_size;

	// for each chunk of the message, decrypt that chunk and go to next chunk
	int curr_byte = 0;
	while (curr_byte < message_bytes) {
		
		int out_bytes = rsa_decrypt_block(keys->d, keys->n, 
			in_block_size, out_block_size, 
			message+curr_byte,
			decrypted+decrypted_bytes);
		
		curr_byte += in_block_size;
		decrypted_bytes += out_block_size;
	}

#ifdef DEBUG
	print_raw("Decrypted message: ", decrypted_bytes, decrypted);
#endif

	return decrypted_bytes;
}


/* *********************** Key I/O functions ******************************* */

// Write the private keys to the given file name 
void rsa_write_private_keys(rsa_keys_t *keys, const char *fname)
{
	FILE *fp = fopen(fname,"w+");
	fprintf(fp,"KEY FILE\n");
	fprintf(fp,"%d %d %d\n", keys->num_bits,
		keys->enc_block_size, keys->dec_block_size);
	
	mpz_out_str(fp,16,keys->p);fprintf(fp,"\n");
	mpz_out_str(fp,16,keys->q);fprintf(fp,"\n");
	mpz_out_str(fp,16,keys->n);fprintf(fp,"\n");
	mpz_out_str(fp,16,keys->d);fprintf(fp,"\n");
	mpz_out_str(fp,16,keys->e);fprintf(fp,"\n");
	
	fclose(fp);
}


// Write the public keys to the given file name
void rsa_write_public_keys(rsa_keys_t *keys, const char *fname)
{
	FILE *fp = fopen(fname,"w+");
	if (fp == NULL) {
		perror("Error - could not write public key");
		exit(-1);
	}
	
	fprintf(fp,"KEY FILE\n");
	fprintf(fp,"%d %d %d\n", keys->num_bits,
		keys->enc_block_size, keys->dec_block_size);
	
	mpz_out_str(fp,16,keys->n); fprintf(fp,"\n");
	mpz_out_str(fp,16,keys->e); fprintf(fp,"\n");
	
	fclose(fp);
}

// Read the private keys from the given file name
void rsa_read_private_keys(rsa_keys_t *keys, const char *fname)
{
	FILE *fp = fopen(fname,"r");
	char inp[1024];
	
	fgets(inp, 1023, fp);
	fscanf(fp,"%d %d %d", &keys->num_bits,
		&keys->enc_block_size, &keys->dec_block_size);
	
	mpz_inits(keys->p, keys->q, keys->n, keys->d, 
		keys->e, NULL);
		
	mpz_inp_str(keys->p,fp, 16); 
	mpz_inp_str(keys->q,fp, 16);
	mpz_inp_str(keys->n,fp, 16);
	mpz_inp_str(keys->d,fp, 16);
	mpz_inp_str(keys->e,fp, 16);
	
	fclose(fp);
}

// Read the public keys from the given file
void rsa_read_public_keys(rsa_keys_t *keys, const char *fname)
{
	FILE *fp = fopen(fname,"r");
	char inp[1024];
	
	fgets(inp, 1023, fp);
	fscanf(fp,"%d %d %d", &keys->num_bits,
		&keys->enc_block_size, &keys->dec_block_size);
	
	mpz_inits(keys->p, keys->q, keys->n, keys->d, 
		keys->e, NULL);
	
	mpz_inp_str(keys->n,fp,16);
	mpz_inp_str(keys->e,fp,16);
	
	print_key("Read n: ", keys->n);
	print_key("Read n: ", keys->e);
	fclose(fp);
}



// FROM: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
//	Compute λ(n) = lcm(λ(p), λ(q)) = lcm(p − 1, q − 1), 
//   where λ is Carmichael's totient function. 
//  This value is kept private.
static void compute_totient(mpz_t lambda, const mpz_t p, const mpz_t q)
{
	mpz_t pm1, qm1;
	mpz_inits(pm1, qm1, NULL);
	
	mpz_sub_ui(pm1, p, 1);
	mpz_sub_ui(qm1, q, 1);
	
	//mpz_lcm(lambda, pm1, qm1);
	mpz_mul(lambda, pm1, qm1);
	
	mpz_clears(pm1, qm1, NULL);
}

// FROM: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
// * Choose an integer e such that 1 < e < λ(n) 
//   and gcd(e, λ(n)) = 1; i.e., e and λ(n) are coprime.
// * Determine d as d ≡ e−1 (mod λ(n)); 
//   i.e., d is the modular multiplicative inverse of e modulo λ(n).
// This means: solve for d the equation d⋅e ≡ 1 (mod λ(n)).
//
// e having a short bit-length and small Hamming weight results in more efficient encryption – most commonly e = 216 + 1 = 65,537. However, much smaller values of e (such as 3) have been shown to be less secure in some settings.[14]
// e is released as the public key exponent.
// d is kept as the private key exponent.
static void compute_keys(rsa_keys_t *keys, const mpz_t lambda)
{
	mpz_t tmp;
	mpz_init(tmp);
	
	// recommendation is to use a fixed e
	mpz_set_ui(keys->e, DEFAULT_E);
	assert(mpz_cmp(keys->e, lambda) < 0);  // e < lambda

	mpz_gcd(tmp, keys->e, lambda);
	//assert(mpz_cmp_ui(tmp, 1) == 0);  // e coprime with lambda
	
	// compute d as modulo mult. inverse
	assert(mpz_invert(keys->d, keys->e, lambda) != 0);

	mpz_clear(tmp);
}


#ifdef linux
// read 128 bytes from /dev/random and initialize the random 
// number generator - only works for linux
static void rsa_init_from_devrandom(gmp_randstate_t state)
{
	long bytes[128];
	mpz_t seed;
	
	FILE *fp = fopen(RANDOM_DEVICE, "rb");
	fread(bytes, sizeof(long), NUM_RANDOM_BYTES , fp);
	fclose(fp);
	
	mpz_init(seed);
	BYTES_TO_MPZ(seed, bytes, NUM_RANDOM_BYTES);
	gmp_randseed(state, seed);
	
	mpz_clear(seed);
}
#endif


// print a raw buffer
static void print_raw(const char *str, int len, const char *raw)
{
	int i;
	printf("%s", str);
	for (i = 0; i < len; i++) {
	   printf("%02x", (unsigned char) raw[i]);
	}
	printf("\n");
}


// print a key
static void print_key(const char *str, const mpz_t key)
{
	printf("%s", str);
        printf("(%lu / %lu)", mpz_sizeinbase(key, 2), mpz_sizeinbase(key, 256));
	printf(" ");	
	mpz_out_str(stdout, 10, key);
	printf(" 0x");
	mpz_out_str(stdout, 16, key);
	printf("\n");
}

/*
Map the number of bits for the key to the chunk size 
that will be encrypted at a time.  There needs to be
a `sufficient` gap between the key size and the
amount of data that can be encrypted in a single round. 
*/
static int compute_enc_block_size(int desired_key_size)
{
	if (desired_key_size <= 8) return 0;
	if (desired_key_size <= 16) return 1;
	if (desired_key_size <= 32) return 2;
	if (desired_key_size <= 64) return 4;
	if (desired_key_size <= 128) return 8;
	if (desired_key_size <= 1024) return 16;
	if (desired_key_size <= 2048) return 32;
	if (desired_key_size <= 4096) return 64;
	return 128;
}

static int compute_dec_block_size(int desired_key_size)
{
	if ((desired_key_size % 8) == 0) return (desired_key_size / 8);
	else return (desired_key_size / 8) + 1;
}

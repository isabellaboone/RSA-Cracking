/*
 * Author: T. Briggs
 * Date: 2019-02-22
 * RSA shared header
 */
#ifndef _RSA_H
#define _RSA_H

#include <gmp.h>

typedef mpz_t rsakey_t;

typedef struct {
	unsigned int num_bits;
	unsigned int enc_block_size;
	unsigned int dec_block_size;
	
	rsakey_t p;
	rsakey_t q;
	rsakey_t n;
	rsakey_t d;
	rsakey_t e;
} rsa_keys_t;

#ifdef linux
// how many byte shall we read from random source
#define RANDOM_DEVICE "/dev/urandom"
#define NUM_RANDOM_BYTES 32
#endif

//#define DEFAULT_E 65537
#define DEFAULT_E 101

void rsa_genkeys(unsigned int num_bits, rsa_keys_t *keys);
size_t rsa_encrypt(char *message, char *encrypted, int message_bytes, rsa_keys_t *keys);
size_t rsa_decrypt(char *message, char *decrypted, int message_bytes, rsa_keys_t *keys);
void rsa_testkeys(rsa_keys_t *keys);

void rsa_read_public_keys(rsa_keys_t *keys, const char *fname);
void rsa_read_private_keys(rsa_keys_t *keys, const char *fname);
void rsa_write_public_keys(rsa_keys_t *keys, const char *fname);
void rsa_write_private_keys(rsa_keys_t *keys, const char *fname);

#endif
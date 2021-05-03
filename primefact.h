/**
 * @file primefact.h
 * @author Isabella Boone 
 * @author John Gable
 * @author Joshua Lewis
 * @brief Header files for primefact.c. 
 * @version 0.1
 * @date 2021-05-02
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include <stdio.h>
#include <math.h> 
#include <stdint.h> // For uint64
#include <stdlib.h> // 
#include <math.h> // maths
#ifndef RSA
#define RSA
#include "rsa.h"

void pollardRho(mpz_t n, rsa_decrypt_t *thread_struct);
void modular_power_mpz(mpz_t var, mpz_t n, mpz_t c);
#endif

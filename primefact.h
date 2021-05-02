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

uint64_t gcd (uint64_t a, uint64_t b);
uint64_t pollardRho(uint64_t n, rsa_decrypt_t *thread_struct); 
int modular_pow(uint64_t base, uint64_t exponent, uint64_t modulus);
#endif

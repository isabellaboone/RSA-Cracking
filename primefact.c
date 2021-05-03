/**
 * @file primefact.c
 * @author Isabella Boone 
 * @author John Gable
 * @author Joshua Lewis
 * @brief Find prime factors of a number using the 
 *   Pollard Rho prime factorization algorithm. 
 * @version 0.2
 * @date 2021-04-29
 * 
 * @copyright Copyright (c) 2021
 * 
 */

// Import 
#include "primefact.h"

/**
 * @brief Calculate (base^exponent)%modulus.  According to geeksforgeeks,
 *   this is the tortise and hare move. 
 * 
 * @param var result to store result in.
 * @param n mpz_t public key 
 * @param c mpz_t randomly generated but used as a constant. 
 */
void modular_power_mpz(mpz_t result, mpz_t n, mpz_t c) {  
  // Create 2 in mpz_t. Maybe an easier way, but I don't know it. 
  mpz_t TWO; 
  mpz_init(TWO); 
  mpz_set_ui(TWO, 2); 

  // Calculate modular power according to 
  mpz_powm(result, result, TWO, n); // modular_pow(x, 2, n)
  mpz_add(result, result, c); // add c
  mpz_add(result, result, n); // add n
  mpz_mod(result, result, n); // var % n
}

/**
 * @brief Find prime factors of a number.
 * 
 * @param n mpz_t number to find primes of.
 * @param thread_struct rsa_decrypt_t struct containing information 
 *   necessary to calculate prime and return information. 
 */
void pollardRho(mpz_t n, rsa_decrypt_t *thread_struct) { 
  // Create constant for 1 and 2 used in calculations 
  mpz_t TWO, ONE; 
  mpz_init(ONE);
  mpz_init(TWO); 
  mpz_set_ui(ONE, 1); 
  mpz_set_ui(TWO, 2); 

  // Return if has already been found
  if(*(thread_struct->found) == 1) { 
    pthread_exit(NULL);
  }

  // Need to initialize a randstate for mpz_urandomb
  gmp_randstate_t state; 
  gmp_randinit_mt(state); 

  // Create & Initialize random number 
  mpz_t rand_s; 
  mpz_init(rand_s); 
    
  // Generate a uniformly distributed random integer in the range 
  // 0 to 2^(mpbitcnt) - 1 inclusively, 128 is bitcnt
  mpz_urandomb(rand_s, state, 128);

  // If n == 1, there is no prime divisor for 1.
  if(!mpz_cmp_ui(n, 1)) { 
    *(thread_struct->found) = 1; // Set flag for found
    mpz_set(thread_struct->p, n); // Set p 
    return; // Return, we've found our divisor
  }  

  // Create mpz_t to store result of n % 2
  mpz_t result_mod_2;
  mpz_init(result_mod_2);
  
  // Calculate n % 2
  mpz_mod_ui(result_mod_2, n, 2); 

  // If n % 2 == 0, n is even, we've found our divisor
  if (!mpz_cmp_ui(result_mod_2, 0)) { 
    *(thread_struct->found) = 1; // Set flag for found 
    mpz_set_ui(thread_struct->p, 2); // Set p
    return; // Return, we've found our divisor 
  }

  // Create & initialize variables to store randomly generated numbers
  mpz_t rand1, rand2; 
  mpz_init(rand1);
  mpz_init(rand2); 

  // Generate random numbers
  mpz_urandomb(rand1, state, 128); 
  mpz_urandomb(rand2, state, 128);

  // Create and initialize variables to perform calculations
  mpz_t x, y, c, d, n_copy; 
  mpz_init(x); 
  mpz_init(y); 
  mpz_init(d); // Just a variable name, albiet confusing 
  mpz_init(c); 
  mpz_init(n_copy); 

  mpz_set(n_copy, n); // Create a copy of n so we can modify it for both calculations

  // Calculate x, x picks from range [2, n)
  mpz_sub(n_copy, n, TWO); // (n - 2)
  mpz_mod(x, rand1, n_copy); // rand % n - 2
  mpz_add(x, x, TWO); // (rand % n - 2) + 2

  // Calculate y, which is a copy of x
  mpz_set(y, x);

  // Caclulate c 
  mpz_sub(n_copy, n, ONE); // n - 1
  mpz_mod(c, rand2, n_copy); // rand % n - 1
  mpz_add(c, c, ONE); // rand % n - 1 + 1

  mpz_set(d, ONE); // Set d = 1

  // While d == 1
  while (!mpz_cmp_ui(d, 1)) { 
    // "Tortise move"
    modular_power_mpz(x, n, c);
    // "Hare move"
    modular_power_mpz(y, n, c); 
    modular_power_mpz(y, n, c); 

    mpz_t abs;
    mpz_sub(abs, x, y); // x - y
    mpz_abs(abs, abs); // abs(x-y)
    mpz_gcd(d, abs, n); //gcd(abs(x-y), n)

    // If gcd(x-y,n) == n, call again
    if(!mpz_cmp(d, n)) {
      return pollardRho(n, thread_struct);
    }
  }
  // d != 1, we found our p value
  *(thread_struct->found) = 1; // Set found flag
  mpz_set(thread_struct->p, d); // Set p
}

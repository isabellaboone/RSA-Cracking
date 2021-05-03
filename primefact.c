/**
 * @file primefact.c
 * @author Isabella Boone 
 * @author John Gable
 * @author Joshua Lewis
 * @brief Find prime factors of a number. 
 * @version 0.1
 * @date 2021-04-29
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "primefact.h"

void modular_power_mpz(mpz_t var, mpz_t n, mpz_t c) {  
  mpz_t TWO; 
  mpz_init(TWO); 
  mpz_set_ui(TWO, 2); 

  mpz_powm(var, var, TWO, n); // modular_pow(x, 2, n)
  mpz_add(var, var, c); // add c
  mpz_add(var, var, n); // add n
  mpz_mod(var, var, n); // var % n
}

void pollardRho(mpz_t n, rsa_decrypt_t *thread_struct) { 
  gmp_printf("n: %Zd\n", n);
  mpz_t TWO, ONE; 
  mpz_init(ONE);
  mpz_init(TWO); 

  mpz_set_ui(TWO, 2); 
  mpz_set_ui(ONE, 1); 
  // Return if has already been found
  if(*(thread_struct->found) == 1) { 
    return;
  }

  // Generate a random number

  // gmp_randinit_mt (gmp_randstate_t state) 
  // Random state means an algorithm selection and current state data.
  gmp_randstate_t state; 
  gmp_randinit_mt(state);

  mpz_t rand_s;
  mpz_init(rand_s); 
    
  // Generate a uniformly distributed random integer in the range 
  // 0 to 2^(mpbitcnt) - 1 inclusively. 
  mpz_urandomb(rand_s, state, 128);

  if(!mpz_cmp_ui(n, 1)) { // No prime divisor for 1
    *(thread_struct->found) = 1; 
    mpz_set(thread_struct->p, n); 
    return; 
  }  

  // Even means one of the divisors is 2
  // maybe don't need since n is always odd
  mpz_t result_mod_2;
  mpz_init(result_mod_2);

  mpz_mod_ui(result_mod_2, n, 2); 
  if (!mpz_cmp_ui(result_mod_2, 0)) { 
    mpz_set_ui(thread_struct->p, 2); 
    *(thread_struct->found) = 1; 
    return; 
  }

  // Create & initialize variables to store random ints for finding x, y etc
  mpz_t rand1, rand2; 
  mpz_init(rand1);
  mpz_init(rand2); 

  // Generate random ints
  mpz_urandomb(rand1, state, 128); 
  mpz_urandomb(rand2, state, 128);

  mpz_t x, y, c, d, n_copy; 
  mpz_init(x); 
  mpz_init(y); 
  mpz_init(d); 
  mpz_init(c); 
  mpz_init(n_copy); 

  mpz_set(n_copy, n); // Create a copy of n

  // maybe should be 3
  // Calculate x -- uint64_t x = (uint64_t)(rand() % (n - 2)) + 2; 
  mpz_sub(n_copy, n, TWO); // (n - 2)
  mpz_mod(x, rand1, n_copy); // rand % n - 2
  mpz_add(x, x, TWO); // (rand % n - 2) + 2

  // Calculate y -- uint64_t y = x; 
  mpz_set(y, x);

  // Caclulate c -- uint64_t c = (uint64_t)rand() % (n - 1) + 1;
  mpz_sub(n_copy, n, ONE); // n - 1
  mpz_mod(y, rand2, n_copy); // rand % n - 1
  mpz_add(y, y, ONE); // rand % n - 1 + 1

  mpz_set(d, ONE); // uint64_t d = 1l; me thinks? 

  while (!mpz_cmp_ui(d, 1)) { 
    modular_power_mpz(x, n, c); 
    modular_power_mpz(y, n, c); 
    modular_power_mpz(y, n, c); 

    // gcd(d, abs(x - y), n); 
    mpz_t abs;
    mpz_sub(abs, x, y); 
    mpz_abs(abs, abs); 
    mpz_gcd(d, abs, n);

    if(!mpz_cmp(d, n)) {
      return pollardRho(n, thread_struct);
    }
  }
  *(thread_struct->found) = 1; 
  mpz_set(thread_struct->p, d);
}


// int main(void) {
//   uint64_t n; 
//   printf("Enter n: \n");
//   scanf("%ld", &n);
//   printf("%lu\n", n);

//   printf("One of the divisors for %lu is %lu\n", n, pollardRho(n));
// }

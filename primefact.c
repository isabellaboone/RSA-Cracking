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

#include <stdio.h>
#include <math.h> 
#include <stdint.h> // For uint64
#include <stdlib.h> // 
#include <math.h> // maths
#include "primefact.h"

uint64_t gcd (uint64_t a, uint64_t b) { 
  return b == 0 ? a : gcd(b, a % b); 
}

/* Iterative Function to calculate (x^y) in O(log y) */
int modular_pow(uint64_t base, uint64_t exponent, uint64_t modulus)
{
    int result = 1;     // Initialize result
  
    while (exponent > 0) {
      // If y is odd, multiply x with result
      if (exponent % 2 == 1)
        result = (result*base) % modulus;
  
      // y must be even now
      exponent = exponent>>1; // y = y/2
      base = (base*base) % modulus;   // Change x to x^2
    }
    return result;
}

uint64_t pollardRho(uint64_t n) { 
  int s = rand(); 
  // No prime divisor for 1
  if(n == 1) {
    return n; 
  }

  // Even means one of the divisors is 2
  if (n % 2 == 0) { 
    return 2; 
  }

  uint64_t x = (uint64_t)(rand() % (n - 2)) + 2; 
  uint64_t y = x; 
  uint64_t c = (uint64_t)rand() % (n - 1) + 1;
  // initialize candidate divisor 
  uint64_t d = 1l; 

  while (d == 1) { 
    x = (modular_pow(x, 2, n) + c + n) % n; 

    y = (modular_pow(y, 2, n) + c + n) % n; 
    y = (modular_pow(y, 2, n) + c + n) % n;

    d = gcd(abs(x - y), n); 

    if(d == n) return pollardRho(n);
  }

  return d; 
}


// int main(void) {
//   uint64_t n; 
//   printf("Enter n: \n");
//   scanf("%ld", &n);
//   printf("%lu\n", n);

//   printf("One of the divisors for %lu is %lu\n", n, pollardRho(n));
// }

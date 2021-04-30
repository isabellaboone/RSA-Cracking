/**
 * @file primefact.c
 * @author Isabella Boone (ib2573@ship.edu)
 * @brief 
 * @version 0.1
 * @date 2021-04-29
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdio.h>
#include <math.h> 

typedef struct { 
  long p; 
  long q; 
} n_t; 

char * find_primes(unsigned long num, char *f) {
  int count = 0; 
  while(!(num % 2 > 0)) { 
    num /= 2;
    count++; 
  }
  if(count > 0) {
    printf("2 %d\n", count);
    // sprintf(f, "2 %d, ", count);
  }
  for(long i = 3; i <= (sqrtl(num)); i += 2) { 
    count = 0; 
    while(num % i == 0) { 
      count++; 
      num /= i; 
    }
    if (count > 0) {
      // sprintf(f, "%ld %d, ", i, count);
      printf("for: %ld %d\n", i, count); 
    }

  }

  if (num > 2) { 
    // sprintf(f, "%ld 1, ", num); 
    printf("last %ld 1", num);
  }
  // printf("%s\n", f);
}

int main(void) {
  unsigned long num; 
  printf("Enter number to find prime factorization of: \n");
  scanf("%ld", &num); 

  printf("Finding prime factors of %lu\n", num);

  char string[1024]; 

  find_primes(num, string); 

  return 0; 
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rsa.h"

#define KEY_LEN 64
#define BLOCK_LEN 32


void print_buff(int len, char *buf)
{
        int i;
        for (i = 0; i < len; i++) {
                printf("%02x", (unsigned char) buf[i]);
        }
}

size_t sizeoffile(const char *fname)
{
  struct stat sbuf;
  int rc = stat(fname, &sbuf);
  if (rc <0) {
    printf("Error -couldnot stat file\n");
    exit(-1);
  }
  return sbuf.st_size;
}

int main(int argc, char **argv)
{
  if (argc != 3) {
    printf("Error - run as decrypt private_fname encrypted_fname\n");
    exit(0);
  }

 
  FILE *fp = fopen(argv[2],"r+");
  if (fp == NULL) {
    perror("could not open encrypted text");
    exit(-1);
  }

  size_t fsize = sizeoffile(argv[2]);
  char *decrypted = malloc(fsize*2);
  char *encrypted = malloc(fsize*2);
  memset(decrypted, 0, fsize*2);
  memset(encrypted, 0, fsize*2);
  
  int bytes = fread(encrypted, 1, fsize, fp);
  printf("Read %d bytes\n", bytes);
  fclose(fp);
  
  rsa_keys_t keys;
  rsa_read_private_keys(&keys,argv[1]);


  printf("Encrypted: ("); print_buff(bytes, encrypted); printf(")\n");
	
  int dec_len = rsa_decrypt(encrypted, decrypted, bytes, &keys);
  printf("Decrypted: ("); print_buff(dec_len, decrypted); printf(")\n");

  decrypted[dec_len] = 0x00;
  printf("%s\n", decrypted);
	
}

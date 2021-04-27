#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

void print_buff(int len, char *buf)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x", (unsigned char) buf[i]);
	}
}


void chomp(char *str)
{
   char *ptr = strchr(str, '\n');
   if (ptr != NULL) { 
     *ptr = '\0';
   }
}
  
#define KEY_LEN 32
#define BLOCK_LEN 32
#define MAX_MSG_LEN 2048

int main(int argc, char **argv)
{

   while (1) {
	rsa_keys_t keys = { 0 };
	char input[MAX_MSG_LEN+1];
	char message[MAX_MSG_LEN+12];
	
	int key_len = KEY_LEN;
	if (argc == 2) {
	   key_len = atoi(argv[1]);
	}
    else {
 	    printf("Enter number of bits: ");
	 	fgets(input, 32, stdin);
	    key_len = atoi(input);
		
		if (key_len <= 0) {
			break;
		}
    }

 	printf("Generating Alice's keys with %d bits\n", key_len);
	rsa_genkeys(key_len, &keys);
	
	memset(input,0, MAX_MSG_LEN);
	memset(message,0, MAX_MSG_LEN);
	strcpy(message,"<h1>");
	
	printf("Enter the message:");
	
	fgets(input,MAX_MSG_LEN-12,stdin);
    chomp(input);

    strncat(message, input, MAX_MSG_LEN-12);
	
    strcat(message, "</h1>");

    printf("Encrypting: (%s)\n", message);

	int len = strlen(message);
	message[len] = 0x0;
	len--;
	
	char *encrypted = malloc((key_len/8) * BLOCK_LEN);
	char *decrypted = malloc((key_len/8) * BLOCK_LEN);

	printf("Encrypting the message using Alice's public key\n");
	int enc_len = rsa_encrypt(message, encrypted, strlen(message)+1, &keys);
	
	printf("Writing the encrypted message.)\n");
	// dumping to file
	char fname[128];
	sprintf(fname,"encrypted-%d.dat", key_len);
	FILE *fp = fopen(fname,"w+");
	fwrite(encrypted,1, enc_len, fp);
	fclose(fp);
	
	printf("Writing Alices keys\n");
	sprintf(fname,"private-%d.txt", key_len);
	rsa_write_private_keys(&keys, fname);
	
	sprintf(fname,"public-%d.txt", key_len);
	rsa_write_public_keys(&keys, fname);
  }
}

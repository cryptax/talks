#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// we wouldn't do it that way in C, but I want the assembly code to be similar to Dart
int shift = 3;

char *encrypt(char *input, int len) {
  char *output = (char*) malloc(sizeof(char)*(len+1));
  for (int i = 0; i < len; i++) {
    output[i] = (input[i] + shift) % 256;
  }
  output[len] = '\0';
  return output;
}

char *decrypt(char *input, int len) {
  shift = -shift;
  char *output = encrypt(input, len);
  shift = -shift;
  return output;
}

void main() {
  char message[] = "Phrack Geeks!";
  int len = strlen(message);
  char encryptedMessage[len+1];

  printf("Welcome to Caesar encryption\n");

  char *encrypted = encrypt(message, len);
  if (encrypted != NULL) {
    printf("Caesar-encrypted: %s\n", encrypted);

    /* Decrypt */
    char *decrypted = decrypt(encrypted, len);
    if (decrypted != NULL) {
      printf("Decrypted message: %s\n", decrypted);
      free(decrypted);
    }
    free(encrypted);
  }
}

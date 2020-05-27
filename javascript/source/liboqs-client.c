#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <emscripten.h>

#include "base64.h"


OQS_KEM *kem = NULL;
unsigned char *ciphertext = NULL;
unsigned char *shared_secret_e = NULL;

EMSCRIPTEN_KEEPALIVE
int Prepare(const char *algo){

	printf("Algo: %s\n", algo);

	kem = OQS_KEM_new(algo);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: not able to initialize with given algo!\n");
		return 1;
	}

	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);

	if ((ciphertext == NULL) || (shared_secret_e == NULL)) {
		fprintf(stderr, "ERROR: malloc failed\n");
		
		OQS_MEM_insecure_free(ciphertext);
		OQS_MEM_insecure_free(shared_secret_e);

		return 1;
	}

	return 0;
}

EMSCRIPTEN_KEEPALIVE
int Encaps(char *public_key){

	if(kem != NULL){

		/* +1 for the NULL terminator. */
		size_t out_len = b64_decoded_size(public_key)+1;

		unsigned char *public_key_decoded = malloc(out_len);

		if(!b64_decode(public_key, public_key_decoded, out_len)){
			fprintf(stderr, "ERROR: decoding failed!\n");
			OQS_MEM_insecure_free(public_key_decoded);
			return 1;
		}

		public_key_decoded[out_len] = '\0'; //NULL terminator


		OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key_decoded);

		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
			if (kem != NULL) {
				OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
			}
			OQS_MEM_insecure_free(public_key_decoded);
			OQS_MEM_insecure_free(ciphertext);

			return 1;
		}

		printf("Success: encryption.\n");

		printf("[Success] aes_key_length: %lu and cipher_text_length: %lu \n", kem->length_shared_secret, kem->length_ciphertext);

		OQS_MEM_insecure_free(public_key_decoded);

		return 0;

	}
	else{
		return 1;
	}
}

EMSCRIPTEN_KEEPALIVE
char *GetAesKey(){
	if(kem != NULL) 
		return b64_encode(shared_secret_e, kem->length_shared_secret);
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
char *GetCipherText(){
	if(kem != NULL) 
		return b64_encode(ciphertext, kem->length_ciphertext);
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
void Cleanup() {
	if (kem != NULL) {
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
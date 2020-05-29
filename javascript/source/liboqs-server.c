#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <emscripten.h>

#include "base64.h"


OQS_KEM *kem = NULL;
unsigned char *public_key = NULL;
unsigned char *secret_key = NULL;

unsigned char *shared_secret_d = NULL;

EMSCRIPTEN_KEEPALIVE
int GenerateKeyPair(const char *algo){
	printf("Algo: %s\n", algo);

	kem = OQS_KEM_new(algo);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: not able to initialize with given algo!\n");
		return 1;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);

	if ((public_key == NULL) || (secret_key == NULL)) {
		fprintf(stderr, "ERROR: malloc failed\n");
		
		OQS_MEM_insecure_free(public_key);
		OQS_MEM_insecure_free(secret_key);

		return 1;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		if (kem != NULL) {
			OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		}
		OQS_MEM_insecure_free(public_key);

		return 1;
	}

	printf("Success: keys generated.\n");

	printf("[Success] public_key_length: %lu and secret_key_length: %lu \n", kem->length_public_key, kem->length_secret_key);

	return 0;

}

EMSCRIPTEN_KEEPALIVE
char *GetPublicKey(){
	if(kem != NULL) 
		return b64_encode(public_key, kem->length_public_key);
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
int Decaps(char *ciphertext){

	if(kem != NULL){

		size_t out_len = b64_decoded_size(ciphertext);
		//+1; //+1 for NULL terminator

		unsigned char *ciphertext_decoded = malloc(out_len);

		if(!b64_decode(ciphertext, ciphertext_decoded, out_len)){
			fprintf(stderr, "ERROR: decoding failed!\n");
			OQS_MEM_insecure_free(ciphertext_decoded);
			return 1;
		}

		//ciphertext_decoded[out_len] = '\0';

		shared_secret_d = malloc(kem->length_shared_secret);

		OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext_decoded, secret_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
			if (kem != NULL) {
				OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
			}
			OQS_MEM_insecure_free(ciphertext_decoded);

			return 1;
		}


		printf("Success: decryption.\n");

		printf("[Success] aes_key_length: %lu \n", kem->length_shared_secret);

		OQS_MEM_insecure_free(ciphertext_decoded);

		return 0;
	}
	else{
		return 1;
	}
}

EMSCRIPTEN_KEEPALIVE
char *GetAesKey(){
	if(kem != NULL) 
		return b64_encode(shared_secret_d, kem->length_shared_secret);
	else
		return "";
}

EMSCRIPTEN_KEEPALIVE
void Cleanup() {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_KEM_free(kem);
}
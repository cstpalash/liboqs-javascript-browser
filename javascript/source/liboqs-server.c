#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <emscripten.h>

#include "base64.h"


OQS_KEM *kem = NULL;
char *public_key_b64 = NULL; // keep base64 encoded public_key returned by GetPublicKey to avoid memory leak

unsigned char *secret_key = NULL;

char *shared_secret_d_b64 = NULL; // keep base64 encoded shared_secret_d returned by GetAesKey to avoid memory leak

EMSCRIPTEN_KEEPALIVE
int GenerateKeyPair(const char *algo){
	printf("Algo: %s\n", algo);

	if (kem != NULL) {
		fprintf(stderr, "ERROR: Call CleanupAll to avoid memory leak\n");
		return 1;
	}

	kem = OQS_KEM_new(algo);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: not able to initialize with given algo!\n");
		return 1;
	}

	unsigned char public_key[kem->length_public_key]; // use stack allocation in favour of heap for local variable
	secret_key = malloc(kem->length_secret_key);

	if (secret_key == NULL) {
		fprintf(stderr, "ERROR: malloc failed\n");
		return 1;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);

		return 1;
	}
	public_key_b64 = b64_encode(public_key, sizeof(public_key));
	if (public_key_b64 == NULL) {
		fprintf(stderr, "ERROR: malloc failed\n");
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);

		return 1;
	}
	printf("Success: keys generated.\n");

	printf("[Success] public_key_length: %lu and secret_key_length: %lu \n", kem->length_public_key, kem->length_secret_key);

	return 0;

}

EMSCRIPTEN_KEEPALIVE
char *GetPublicKey(){
	if(public_key_b64 != NULL)
		return public_key_b64;
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
int Decaps(char *ciphertext){

	if(kem == NULL)
		return 1;

	if (shared_secret_d_b64 != NULL) {
		fprintf(stderr, "ERROR: Call CleanupDecaps to avoid memory leak\n");
		return 1;
	}

	size_t out_len = b64_decoded_size(ciphertext);

	unsigned char ciphertext_decoded[out_len];

	if(!b64_decode(ciphertext, ciphertext_decoded, out_len)){
		fprintf(stderr, "ERROR: decoding failed!\n");
		return 1;
	}

	unsigned char shared_secret_d[kem->length_shared_secret];

	OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext_decoded, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		OQS_MEM_cleanse(shared_secret_d, kem->length_shared_secret);

		return 1;
	}
	shared_secret_d_b64 = b64_encode(shared_secret_d, sizeof(shared_secret_d));
	if (shared_secret_d_b64 == NULL) {
		fprintf(stderr, "ERROR: malloc failed\n");
		OQS_MEM_cleanse(shared_secret_d, kem->length_shared_secret);

		return 1;
	}

	printf("Success: decryption.\n");

	printf("[Success] aes_key_length: %lu \n", kem->length_shared_secret);

	return 0;
}

EMSCRIPTEN_KEEPALIVE
char *GetAesKey(){
	if (shared_secret_d_b64 != NULL)
		return shared_secret_d_b64;
	else
		return "";
}

EMSCRIPTEN_KEEPALIVE
void CleanupDecaps() {
	if (kem != NULL) {
		OQS_MEM_secure_free(shared_secret_d_b64, b64_encoded_size(kem->length_shared_secret));
		shared_secret_d_b64 = NULL;
	}
}

EMSCRIPTEN_KEEPALIVE
void CleanupAll() {
	CleanupDecaps();
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		secret_key = NULL;
	}
	OQS_MEM_insecure_free(public_key_b64);
	public_key_b64 = NULL;
	OQS_KEM_free(kem);
	kem = NULL;
}

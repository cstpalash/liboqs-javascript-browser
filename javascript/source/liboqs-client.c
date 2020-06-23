#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include <emscripten.h>

#include "base64.h"


OQS_KEM *kem = NULL;
char *ciphertext_b64 = NULL; // keep base64 encoded ciphertext returned by GetCipherText to avoid memory leak
char *shared_secret_e_b64 = NULL; // same for GetAesKey

EMSCRIPTEN_KEEPALIVE
int Prepare(const char *algo){

	printf("Algo: %s\n", algo);

	kem = OQS_KEM_new(algo);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: not able to initialize with given algo!\n");
		return 1;
	}
	return 0;
}

EMSCRIPTEN_KEEPALIVE
int Encaps(char *public_key) {

	if (kem == NULL) {
		fprintf(stderr, "ERROR: Call Prepare first\n");
		return 1;
	}

	if (ciphertext_b64 != NULL || shared_secret_e_b64 != NULL) {
		fprintf(stderr, "ERROR: Call CleanupEncaps to avoid memory leak\n");
		return 1;
	}

	unsigned char public_key_decoded[b64_decoded_size(public_key)]; // use stack allocation in favour of heap
	if (!b64_decode(public_key, public_key_decoded, sizeof(public_key_decoded))) {
		fprintf(stderr, "ERROR: b64_decode of public_key failed\n");
		return 1;
	}

	unsigned char ciphertext[kem->length_ciphertext];
	unsigned char shared_secret_e[kem->length_shared_secret];

	OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key_decoded);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		return 1;
	}

	ciphertext_b64 = b64_encode(ciphertext, sizeof(ciphertext));
	shared_secret_e_b64 = b64_encode(shared_secret_e, sizeof(shared_secret_e));
	OQS_MEM_cleanse(shared_secret_e, sizeof(shared_secret_e));

	if (ciphertext_b64 == NULL || shared_secret_e_b64 == NULL) {
		fprintf(stderr, "ERROR: malloc failed\n");
		OQS_MEM_insecure_free(ciphertext_b64);
		OQS_MEM_secure_free(shared_secret_e_b64, b64_encoded_size(sizeof(shared_secret_e)));
		return 1;
	}

	printf("Success: encryption.\n");

	printf("[Success] aes_key_length: %lu and cipher_text_length: %lu \n", kem->length_shared_secret, kem->length_ciphertext);

	return 0;
}

EMSCRIPTEN_KEEPALIVE
char *GetAesKey(){
	if (shared_secret_e_b64 != NULL)
		return shared_secret_e_b64;
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
char *GetCipherText(){
	if (ciphertext_b64 != NULL)
		return ciphertext_b64;
	else
		return "";
}


EMSCRIPTEN_KEEPALIVE
void CleanupEncaps() {
	if (kem != NULL) {
		OQS_MEM_secure_free(shared_secret_e_b64, b64_encoded_size(kem->length_shared_secret));
		shared_secret_e_b64 = NULL;
	}
	OQS_MEM_insecure_free(ciphertext_b64);
	ciphertext_b64 = NULL;
}

EMSCRIPTEN_KEEPALIVE
void CleanupAll() {
	CleanupEncaps();
	OQS_KEM_free(kem);
	kem = NULL;
}

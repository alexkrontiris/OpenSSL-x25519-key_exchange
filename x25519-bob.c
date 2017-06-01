/*
 * Creating elliptic curve (x25519) cryptography key pairs
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

int main() {
	
	/* Generate private and public keys */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);

	/* Print keys to stdout */
	printf("\nBob's PRIVATE KEY:\n");
	PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
	printf("\nBob's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, pkey);

	/* Write public key to file */
	BIO *out;
	out = BIO_new_file("pubkey-bob.txt", "w+");
	
	if (!out) {
		/* Error */
		printf("BIO out is empty\n");
	}
	PEM_write_bio_PUBKEY(out, pkey);
	BIO_flush(out);

	/* Read Alice's public key */
	FILE *keyfile = fopen("pubkey-alice.txt", "r");
	EVP_PKEY *peerkey = NULL;
	peerkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
	printf("\nAlice's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, peerkey);
	
	/* Generate shared secret */
	EVP_PKEY_CTX *ctx;
	unsigned char *skey;
    size_t skeylen;   
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx) {
		/* Error */
        printf("CTX is empty");
    }
        
    if (EVP_PKEY_derive_init(ctx) <= 0) { 
		/* Error */
        printf("EVP derive initialization failed\n");
    }
        
	if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) { 
		/* Error */
		printf("EVP derive set peer failed\n");
    }
        
	/* Determine buffer length */
    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
		/* Error */
		printf("EVP derive failed\n");
    }
    skey = OPENSSL_malloc(skeylen);
     
	if (!skey) {
		/* Malloc failure */
		printf("OpenSSL Malloc failed");
	}
    
	if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
		/* Error */
		printf("Shared key derivation failed");
	}
	printf("\nShared secret:\n");
	
	for (size_t i = 0; i < skeylen; i++) {
        printf("%02x", skey[i]);
	}
	
	return 0;
}

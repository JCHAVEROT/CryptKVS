/**
 * @file ckvs_crypto.c
 * @brief c.f. ckvs_crypto.h
 */
#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"

// ----------------------------------------------------------------------
int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd) {
    //check pointers
    if (mr == NULL || key == NULL || pwd == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }
    //initialize the ckvs memrecord
    memset(mr, 0, sizeof(ckvs_memrecord_t));

    //creation of the stretched_key in format key|password
    char *str = calloc(2 * CKVS_MAXKEYLEN + 2, 1);
    if (str == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    strncpy(str, key, strlen(key));
    strcat(str, "|");
    strncat(str, pwd, strlen(pwd));

    //convertion of the stretched_key in SHA256, stored in the memrecord
    SHA256((unsigned char *) str, strlen(str), mr->stretched_key.sha);

    free(str);


    //computation of the auth_key from the SHA256 of the stretched_key with message AUTH_MESSAGE
    int a =HMAC_and_check(mr->stretched_key.sha,(const unsigned char *) AUTH_MESSAGE,strlen(AUTH_MESSAGE),mr->auth_key.sha);
    if (a!=ERR_NONE){
        return a;
    }

    //computation of c1 from the SHA256 of the stretched_key with message C1_MESSAGE
    a =HMAC_and_check(mr->stretched_key.sha,(const unsigned char *) C1_MESSAGE,strlen(C1_MESSAGE), mr->c1.sha);
    if (a!=ERR_NONE){
        return a;
    }

    return ERR_NONE;
}

int HMAC_and_check(unsigned char* sha1,const unsigned char * message,size_t message_len,unsigned char* sha2 ){
    if (sha1==NULL || message==NULL || sha2==NULL){
        return ERR_INVALID_ARGUMENT;
    }
    unsigned int l=0;
    HMAC(EVP_sha256(),sha1, SHA256_DIGEST_LENGTH, message,
         message_len, sha2, &l);

    //verify the length
    if (l != SHA256_DIGEST_LENGTH) {
        //error
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2) {
    //check pointers
    if (mr == NULL || c2 == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //computation of the master_key from the SHA256 of the auth_key with the sha of c2 as message
    int a =HMAC_and_check(mr->c1.sha,c2->sha,SHA256_DIGEST_LENGTH,mr->master_key.sha);
    if (a!=ERR_NONE){
        return a;
    }

    return ERR_NONE;

}

// ----------------------------------------------------------------------
int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen) {
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    // Now we can set key and IV
    const unsigned char *const key = (const unsigned char *) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}

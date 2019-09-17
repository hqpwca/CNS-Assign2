#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>

#include "include/crypto.h"

Crypto::Crypto()
{
    strcpy((char *)salt, "KCl");

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
}

void Crypto::set_key(){
    std::string pass;

    std::cerr << "Password: ";
    std::cin >> pass;
    set_key(pass.c_str());
}

void Crypto::set_key(const char *password){
    memset(generated_key, 0, sizeof(generated_key));

    strcpy(raw_password, password);

    PKCS5_PBKDF2_HMAC(raw_password, strlen((const char *)raw_password), salt, strlen((const char*)salt), PBKDF2_ITER, EVP_sha512(), KEY_LEN, generated_key);

    std::cerr << "Generated Key: ";
    std::cerr << std::hex << std::uppercase;
    for(int i=0; i < KEY_LEN; ++i){
        std::cerr << std::setfill('0') << std::setw(2)  << (int)generated_key[i] << ' ';
    }
    std::cerr << std::endl;
}

int Crypto::generate_IV(unsigned char* IV){
    return RAND_bytes(IV, AES_BLOCK_SIZE);
}

int Crypto::AES_encrypt(const unsigned char *input, unsigned char *output, unsigned char *sIV, int input_len){
    memset(output, 0, sizeof(output));
    int output_len, len;

    generate_IV(sIV);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, generated_key, sIV);
    EVP_EncryptUpdate(ctx, output, &len, input, input_len);
    output_len = len;
    EVP_EncryptFinal_ex(ctx, output + len, &len);
    output_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return output_len;
}

int Crypto::AES_decrypt(const unsigned char *input, unsigned char *output, unsigned char *sIV, int input_len){
    memset(output, 0, sizeof(output));
    int output_len, len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, generated_key, sIV);
    EVP_DecryptUpdate(ctx, output, &len, input, input_len);
    output_len = len;
    EVP_DecryptFinal_ex(ctx, output + len, &len);
    output_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return output_len;

}

int Crypto::HMAC_generate(const unsigned char *input, unsigned char *HMAC, int len){
    unsigned output_len = HMAC_LEN;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, generated_key, strlen((char *)generated_key), EVP_sha512(), NULL);
    HMAC_Update(ctx, input, len);
    HMAC_Final(ctx, HMAC, &output_len);
    HMAC_CTX_free(ctx);
    
    return 1;
}

Crypto::~Crypto(){

}
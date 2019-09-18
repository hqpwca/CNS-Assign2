#ifndef CRYPTO_H
#define CRYPTO_H

#define BUFSIZE 256
#define KEY_LEN 32
#define MAX_INPUT_LEN 65536
#define PBKDF2_ITER 4096
#define HMAC_LEN 64
#define IV_LEN 16

#include <openssl/aes.h>

class Crypto {
    char raw_password[64];
    unsigned char generated_key[KEY_LEN];

    unsigned char IV[AES_BLOCK_SIZE];

    unsigned char salt[10];

public:
    Crypto();

    void set_key();
    void set_key(const char *password);

    void SHA_512(const unsigned char *input, int input_len, std::string type);

    int generate_IV(unsigned char* IV);
    int AES_encrypt(const unsigned char *input, unsigned char *output, unsigned char *sIV, int input_len);
    int AES_decrypt(const unsigned char *input, unsigned char *output, unsigned char *sIV, int input_len);

    int HMAC_generate(const unsigned char *input, unsigned char *HMAC, int len);

    ~Crypto();
};

#endif

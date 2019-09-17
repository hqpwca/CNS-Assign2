#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

#include "include/crypto.h"
#include "include/network.h"

using namespace std;

Crypto decoder;
Network net;

static inline bool try_open_file(string filename){
    ifstream tfi(filename);
    return tfi.good();
}

int main(int argc, char** argv)
{
    if(argc <= 2 || argc >= 5){
        cerr << "Wrong Arguments!" << endl;
        return -1;
    }

    bool local = true;
    string filename = argv[1];
    string type = argv[2];
    int port;
    if(argc == 4) {
        sscanf(argv[3], "%d", &port);
        local = false;
    }

    unsigned char buffer[MAX_INPUT_LEN + HMAC_LEN + IV_LEN];

    unsigned char plaintext[MAX_INPUT_LEN];
    unsigned char ciphertext[MAX_INPUT_LEN];
    unsigned char IV[IV_LEN];
    unsigned char HMAC[HMAC_LEN];
    unsigned char cHMAC[HMAC_LEN];

    memset(buffer, 0, sizeof(buffer));
    memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(IV, 0, sizeof(IV));
    memset(HMAC, 0, sizeof(HMAC));
    memset(cHMAC, 0, sizeof(cHMAC));

    if(local)
    {
        string input_filename = filename;
        string rend = input_filename.substr(input_filename.length() - 3);
        if(rend != ".uf"){
            cerr << "Wrong filename extensions!";
            return -1;
        }
        string output_filename = input_filename.substr(0, input_filename.length() - 3);

        if(!try_open_file(input_filename)){
            cerr << "Input file not exists!" << endl;
            return -1;
        }

        if(try_open_file(output_filename)){
            cerr << "Output file already exists." << endl;
            return 33;
        }


        ifstream fi(input_filename, ios::binary);
        ofstream fo(output_filename, ios::binary);

        struct stat *sin = new struct stat;
        stat(input_filename.c_str(), sin);

        fi.read((char *)buffer, sin->st_size);

        memcpy(IV, buffer , IV_LEN);
        memcpy(ciphertext, buffer + IV_LEN, sin->st_size - HMAC_LEN - IV_LEN);
        memcpy(HMAC, buffer + sin->st_size - HMAC_LEN, HMAC_LEN);

        int inlen = sin->st_size - HMAC_LEN - IV_LEN;

        decoder.set_key();
        decoder.HMAC_generate(ciphertext, cHMAC, inlen);
        if(memcmp(HMAC, cHMAC, HMAC_LEN)){
            cerr << "HMAC matching failed!" << endl;
            return 62;
        }
        int outlen = decoder.AES_decrypt(ciphertext, plaintext, IV, inlen);

        fo.write((char *)plaintext, outlen);
        struct stat *sout = new struct stat;
        stat(output_filename.c_str(), sout);

        fprintf(stderr, "Successfully decrypted %s(%ld bytes) to %s(%ld bytes).\n", input_filename.c_str(), sin->st_size, output_filename.c_str(), sout->st_size);

        fi.close();
        fo.close();
    }
    else {
        string output_filename = filename;

        if(try_open_file(output_filename)){
            cerr << "Output file already exists." << endl;
            return 33;
        }

        ofstream fo(output_filename, ios::binary);

        int msg_len = net.Listen_Receive(buffer, port);

        memcpy(IV, buffer , IV_LEN);
        memcpy(ciphertext, buffer + IV_LEN, msg_len - HMAC_LEN - IV_LEN);
        memcpy(HMAC, buffer + msg_len - HMAC_LEN, HMAC_LEN);

        int inlen = msg_len - HMAC_LEN - IV_LEN;

        decoder.set_key();
        decoder.HMAC_generate(ciphertext, cHMAC, inlen);
        if(memcmp(HMAC, cHMAC, HMAC_LEN)){
            cerr << "HMAC matching failed!" << endl;
            return 62;
        }
        int outlen = decoder.AES_decrypt(ciphertext, plaintext, IV, inlen);

        fo.write((char *)plaintext, outlen);
        struct stat *sout = new struct stat;
        stat(output_filename.c_str(), sout);

        fprintf(stderr, "Successfully received and decrypted to %s(%ld bytes).\n", output_filename.c_str(), sout->st_size);

        fo.close();
    }

    return 0;
}
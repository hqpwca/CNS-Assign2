#include <iostream>
#include <fstream>
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

Crypto encoder;
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
    string input_filename = argv[1];
    string type = argv[2];
    string ip_port;
    if(argc == 4) {
        ip_port = argv[3];
        local = false;
    }

    string output_filename = input_filename + ".uf";

    if(!try_open_file(input_filename)){
        cerr << "Input file not exists!" << endl;
        return -1;
    }

    if(try_open_file(output_filename)){
        cerr << "Output file already exists." << endl;
        return 33;
    }

    unsigned char plaintext[MAX_INPUT_LEN];
    unsigned char ciphertext[MAX_INPUT_LEN];
    unsigned char IV[IV_LEN];
    unsigned char HMAC[HMAC_LEN];

    memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(IV, 0, sizeof(IV));
    memset(HMAC, 0, sizeof(HMAC));

    ifstream fi(input_filename, ios::binary);
    ofstream fo(output_filename, ios::binary);

    struct stat *sin = new struct stat;
    stat(input_filename.c_str(), sin);

    fi.read((char *)plaintext, sin->st_size);

    encoder.set_key();
    int outlen = encoder.AES_encrypt(plaintext, ciphertext, IV, sin->st_size);
    encoder.HMAC_generate(ciphertext, HMAC, outlen);

    fo.write((char *)IV, IV_LEN);
    fo.write((char *)ciphertext, outlen);
    fo.write((char *)HMAC, HMAC_LEN);

    struct stat *sout = new struct stat;
    stat(output_filename.c_str(), sout);

    fprintf(stderr, "Successfully encrypted %s(%ld bytes) to %s(%ld bytes).\n", input_filename.c_str(), sin->st_size, output_filename.c_str(), sout->st_size);

    if(!local)
    {
        string IP, portstr;
        for(int i=0; i<ip_port.length(); ++i){
            if(ip_port[i] == ':'){
                IP = ip_port.substr(0, i);
                portstr = ip_port.substr(i+1);
                break;
            }
        }
        int port;
        sscanf(portstr.c_str(), "%d", &port);

        unsigned char *f = (unsigned char *)malloc(sout->st_size);
        memcpy(f, IV, IV_LEN);
        memcpy(f + IV_LEN, ciphertext, outlen);
        memcpy(f + IV_LEN + outlen, HMAC, HMAC_LEN);

        net.Send(f, sout->st_size, IP, port);
    }
 
    fi.close();
    fo.close();
    return 0;
}
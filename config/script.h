#pragma once

#include "openssl/rand.h"
#include "openssl/aes.h"
#include "base64.hpp"
#include <iostream>
#include "strings.h"
#include <fstream>
#include <unordered_map>
#include <unistd.h>

#define KEYSIZE 32
#define KEYLENGTH 256

class Script {
  public:
    std::string encrypt(std::string input);
    Script(){};
    ~Script(){};
    void readfile();
  protected:
    unsigned char _key[KEYSIZE];
    unsigned char _iv[KEYSIZE];
    void gen_key();
    void gen_iv();
    void erb_h();
    void erb_cpp();
    std::unordered_map<std::string, std::string> hashtable;
    std::string xor_char(unsigned char *input);
    };
}// namespace ActiveSecret

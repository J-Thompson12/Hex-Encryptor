#pragma once
#define STRING_HEADER "strings.h"
// use macro to decrypt strings at runtime
#define DECRYPT_STRING(x) ActiveSecret::Aes::decrypt(x)
#define KEYLENGTH 256

#include "openssl/rand.h"
#include "openssl/aes.h"
#include "base64.hpp"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unistd.h>
#include STRING_HEADER

namespace ActiveSecret {
class Aes {
  public:
    std::string encrypt(std::string input);
    static std::string decrypt(std::string input);
    Aes(){};
    ~Aes(){};
  protected:
    static std::string xor_string(std::string input);
};
}// namespace ActiveSecret

#include <string>

#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/conf.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include <cassert>

#define ASSERT assert
//#include "openssl/engine.h"

namespace ActiveSecret {
class Asymmetric{
  public:
    Asymmetric();
    ~Asymmetric();
    std::string encrypt(std::string input);
    std::string decrypt(std::string input);
  private:
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key;
    unsigned char *ek;
    int ekLen;
    unsigned char *iv;
    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
    using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
    void handleErrors();
    int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len, unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv, unsigned char *ciphertext);
    void gen_key();
    void gen_iv();
  
};
}//ActiveSecret

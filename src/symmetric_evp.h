#include <string>

#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/conf.h"

#define initialize ActiveSecret::Symmetric enc
#define test(a) enc.encrypt(a)

namespace ActiveSecret {
class Symmetric {
  public:
    std::string encrypt(const std::string &input);
    std::string decrypt(const std::string &input);
    Symmetric();
    ~Symmetric();
  protected:
    unsigned char _key[128];
    unsigned char _iv[128];
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    void handleErrors();
    unsigned char *encrypt(const unsigned char *input, const int *input_len, int *output_len);
    unsigned char *decrypt(const unsigned char *input, const int *input_len, int *output_len);
    void gen_key();
    void gen_iv();
};
}// namespace ActiveSecret

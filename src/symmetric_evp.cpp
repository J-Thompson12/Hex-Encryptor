#include "symmetric_evp.h"

namespace ActiveSecret {

  Symmetric::Symmetric(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    gen_key();
    gen_iv();
    encrypt_ctx = EVP_CIPHER_CTX_new();
    decrypt_ctx = EVP_CIPHER_CTX_new();
    
    if (!EVP_EncryptInit(encrypt_ctx, EVP_aes_256_cbc(), _key, _iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("AEScrypter: &encrypt_ctx EVP_EncryptInit failed!");
    }

    if (!EVP_DecryptInit(decrypt_ctx, EVP_aes_256_cbc(), _key, _iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("EVP_DecryptInit failed!");
    }
  }
  
  std::string Symmetric::encrypt(const std::string &input){
    int output_size;
    int input_size = input.size();
    unsigned char *output_uchar;
    unsigned char *input_uchar_ptr = (unsigned char *) (input.data());

    output_uchar = encrypt(input_uchar_ptr, &(input_size), &(output_size));

    std::string output(output_uchar, output_uchar + output_size);
    return output;
  }
  
  std::string Symmetric::decrypt(const std::string &input) {
    int output_size;
    int input_size = input.size();
    unsigned char *output_uchar;
    unsigned char *input_uchar_ptr = (unsigned char *) (input.data());

    output_uchar = decrypt(input_uchar_ptr, &(input_size), &(output_size));

    std::string output(output_uchar, output_uchar + output_size);
    return output;
}
  
  unsigned char *Symmetric::encrypt(const unsigned char *input, const int *input_len, int *output_len)
  {
    int encrypted_text_len = 0;
    int encrypted_text_pad_len = 0;;

    unsigned char *encrypted_text;
    encrypted_text = new unsigned char[*input_len + AES_BLOCK_SIZE];
    memset(encrypted_text, 0, *input_len + AES_BLOCK_SIZE);

    if (!EVP_EncryptUpdate(encrypt_ctx, encrypted_text, &encrypted_text_len, input, *input_len)) {
        handleErrors();
    }
    
    if (!EVP_EncryptFinal_ex(encrypt_ctx, encrypted_text + encrypted_text_len, &encrypted_text_pad_len)) {
        handleErrors();
    }

    if (output_len != nullptr)
        *output_len = encrypted_text_len + encrypted_text_pad_len;
    else
        throw std::runtime_error("output_len is nullptr!");

    return encrypted_text;

  }
  
  unsigned char *Symmetric::decrypt(const unsigned char *input, const int *input_len, int *output_len) {
    int decrypted_text_len = 0;
    int decrypted_text_pad_len = 0;;

    unsigned char *decrypted_text;
    decrypted_text = new unsigned char[*input_len];
    memset(decrypted_text, 0, *input_len);

    if (!EVP_DecryptUpdate(decrypt_ctx, decrypted_text, &decrypted_text_len, input, *input_len)) {
        ERR_print_errors_fp(stderr);
        delete[] decrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherUpdate() failed!");
    }

    if (!EVP_DecryptFinal_ex(decrypt_ctx, decrypted_text + decrypted_text_len, &decrypted_text_pad_len)) {
        ERR_print_errors_fp(stderr);
        delete[] decrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherFinal_ex() failed!");
    }

    if (output_len != nullptr)
        *output_len = decrypted_text_len + decrypted_text_pad_len;
    else
        throw std::runtime_error("AESCrypter: crypt(): output_len is nullptr!");

    return decrypted_text;
}

  void Symmetric::gen_key(){
    RAND_bytes(_key, sizeof(_key));
  }
  
  void Symmetric::gen_iv(){
    RAND_bytes(_iv, sizeof(_iv));
  }
  
  void Symmetric::handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
  }
  Symmetric::~Symmetric(){
    EVP_cleanup();
    ERR_free_strings();
    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
  }
  
}

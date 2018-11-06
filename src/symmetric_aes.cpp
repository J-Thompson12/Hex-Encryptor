#include "symmetric_aes.h"

namespace ActiveSecret {


  // un-obfuscates key and iv
  std::string Aes::xor_string(std::string input){
    std::string data = base64::decode(input);
    
    int key = 256;
    for(int i = 0; i < data.size(); i++){
      data[i] = data[i] ^ key;
    }
    for(int i = 0; i < data.size(); i++){
      data[i] = data[i] ^ key - 27;
    }
    return data;
  }

  // can be called during runtime to encrypt strings in RAM
  std::string Aes::encrypt(std::string input){
    size_t inputlength = input.size();
    int RequiredPadding = (AES_BLOCK_SIZE - (inputlength % AES_BLOCK_SIZE));
    unsigned char *plain_data = (unsigned char *) (input.data());
    unsigned char enc_out[inputlength + RequiredPadding];
    memset(enc_out, 0, sizeof(enc_out));

    std::string unencrypted_key = xor_string(key);
    unsigned char *key1 = (unsigned char *) (unencrypted_key.data());
    
    std::string unencrypted_iv = xor_string(iv);
    unsigned char *iv1 = (unsigned char *) (unencrypted_iv.data());

    AES_KEY* enc_key = new AES_KEY();
    AES_set_encrypt_key(key1, KEYLENGTH, enc_key);
    const size_t encslength = ((inputlength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    AES_cbc_encrypt(plain_data, enc_out, encslength, enc_key, iv1, AES_ENCRYPT);

    auto base64string = base64::encode(enc_out, sizeof(enc_out));
    return base64string;
  }

  // can be used during runtime but is also used to decrypt any strings encrypted at buildtime
  std::string Aes::decrypt(std::string input){

    auto base64string = base64::decode(input);
    size_t inputlength = base64string.size();
    unsigned char *enc_data = (unsigned char *) (base64string.data());
    unsigned char dec_out[inputlength];
    memset(dec_out, 0, sizeof(dec_out));
    
    std::string unencrypted_key = xor_string(key);
    unsigned char *key1 = (unsigned char *) (unencrypted_key.data());
    
    std::string unencrypted_iv = xor_string(iv);
    unsigned char *iv1 = (unsigned char *) (unencrypted_iv.data());

    AES_KEY dec_key;
    AES_set_decrypt_key(key1, KEYLENGTH, &dec_key);
    const size_t encslength = ((inputlength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    AES_cbc_encrypt(enc_data, dec_out, encslength, &dec_key, iv1, AES_DECRYPT);

    std::string output(dec_out, dec_out + inputlength);

    return output;

  }


}

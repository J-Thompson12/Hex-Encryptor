#include "asymmetric_evp.h"
#include <iostream>

namespace ActiveSecret {

  Asymmetric::Asymmetric(){
      key = EVP_PKEY_new();
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
      EVP_PKEY_keygen_init(ctx);
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096); // RSA 4096
      // generate key
      EVP_PKEY_keygen(ctx, &key);
    }
  
  std::string Asymmetric::encrypt(std::string input){
    
    BIO *publicBIO = BIO_new(BIO_s_mem());
    // dump key to IO
    PEM_write_bio_PUBKEY(publicBIO, key);
    // get buffer length
    int publicKeyLen = BIO_pending(publicBIO);
    // create char reference of public key length
    unsigned char *publicKeyChar = (unsigned char *) malloc(publicKeyLen);
    // read the key from the buffer and put it in the char reference
    BIO_read(publicBIO, publicKeyChar, publicKeyLen);
    
    BIO *rsaPublicBIO = BIO_new_mem_buf(publicKeyChar, -1);
    // create a RSA object from public key char array
    RSA *rsaPublicKey = NULL;
    PEM_read_bio_RSA_PUBKEY(rsaPublicBIO, &rsaPublicKey, NULL, NULL);
    // create public key
    EVP_PKEY *publicKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(publicKey, rsaPublicKey);
    // initialize encrypt context
    EVP_CIPHER_CTX *rsaEncryptCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsaEncryptCtx);
    
    
    // variables for where the encrypted secret, length, and IV reside
    ek = (unsigned char *) malloc(EVP_PKEY_size(publicKey));
    ekLen = 0;
    iv = (unsigned char *) malloc(EVP_MAX_IV_LENGTH);
    // generate AES secret, and encrypt it with public key
    EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), &ek, &ekLen, iv, &publicKey, 1);
    // encrypt a message with AES secret
    const unsigned char* inputChar = (const unsigned char*) input.c_str();
    // length of message
    int inputlen = input.size();
    // create char reference for where the encrypted message will reside
    unsigned char *encryptedMessage = (unsigned char *) malloc(EVP_MAX_IV_LENGTH);
    
    // the length of the encrypted message
    int encryptedMessageLen = 0;
    int encryptedBlockLen = 0;
    // encrypt message with AES secret
    EVP_SealUpdate(rsaEncryptCtx, encryptedMessage, &encryptedBlockLen, inputChar, inputlen);
    encryptedMessageLen = encryptedBlockLen;
    // finalize by encrypting the padding
    EVP_SealFinal(rsaEncryptCtx, encryptedMessage + encryptedBlockLen, &encryptedBlockLen);
    encryptedMessageLen += encryptedBlockLen;
    
    EVP_CIPHER_CTX_free(rsaEncryptCtx);
    free(encryptedMessage);
    free(publicKeyChar);
    
    std::string output(encryptedMessage, encryptedMessage + encryptedMessageLen);
    
    return output;
  }

  std::string Asymmetric::decrypt(std::string input){
  
    int inputLen = input.size();
    unsigned char *encryptedMessage = (unsigned char *) (input.data());
    
    BIO *privateBIO = BIO_new(BIO_s_mem());
    // dump key to IO
    PEM_write_bio_PrivateKey(privateBIO, key, NULL, NULL, 0, 0, NULL);
    // get buffer length
    int privateKeyLen = BIO_pending(privateBIO);
    // create char reference of private key length
    unsigned char *privateKeyChar = (unsigned char *) malloc(privateKeyLen);
    // read the key from the buffer and put it in the char reference
    BIO_read(privateBIO, privateKeyChar, privateKeyLen);
    unsigned char *rsaPrivateKeyChar = privateKeyChar;
    // write char array to BIO
    BIO *rsaPrivateBIO = BIO_new_mem_buf(rsaPrivateKeyChar, -1);
    // create a RSA object from private key char array
    RSA *rsaPrivateKey = NULL;
    PEM_read_bio_RSAPrivateKey(rsaPrivateBIO, &rsaPrivateKey, NULL, NULL);
    // create private key
    EVP_PKEY *privateKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privateKey, rsaPrivateKey);
    // initialize decrypt context
    EVP_CIPHER_CTX *rsaDecryptCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsaDecryptCtx);
    // decrypt EK with private key, and get AES secretp
    EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, ekLen, iv, privateKey);
    // variable for where the decrypted message with be outputed to
    unsigned char *decryptedMessage = (unsigned char *) malloc(EVP_MAX_IV_LENGTH);
    // the length of the encrypted message
    int decryptedMessageLen = 0;
    int decryptedBlockLen = 0;
    // decrypt message with AES secret
    EVP_OpenUpdate(rsaDecryptCtx, decryptedMessage, &decryptedBlockLen, encryptedMessage, inputLen);
    decryptedMessageLen = decryptedBlockLen;
    // finalize by decrypting padding
    EVP_OpenFinal(rsaDecryptCtx, decryptedMessage + decryptedBlockLen, &decryptedBlockLen);
    decryptedMessageLen += decryptedBlockLen;
  
    std::string output(decryptedMessage, decryptedMessage + decryptedMessageLen);
    free(privateKeyChar);
    free(ek);
    free(iv);
    free(decryptedMessage);
    return output;
  }
  
  void Asymmetric::handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
  }
  
  Asymmetric::~Asymmetric(){
    EVP_cleanup();
    ERR_free_strings();
    EVP_PKEY_CTX_free(ctx);
  }
}

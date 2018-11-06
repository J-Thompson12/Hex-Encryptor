#define KEYSIZE 32
#define KEYLENGTH 256

#include "openssl/rand.h"
#include "openssl/aes.h"
#include "base64.hpp"
#include <iostream>
#include <fstream>
#include <unordered_map>

  unsigned char _key[KEYSIZE];
  unsigned char _iv[KEYSIZE];
  std::unordered_map<std::string, std::string> hashtable;

// generates random key
  void gen_key(){
    RAND_bytes(_key, sizeof(_key));
  }

// generates random iv
  void gen_iv(){
    RAND_bytes(_iv, sizeof(_iv));
  }

// encrypts strings using AES CBC 256
  std::string encrypt(std::string input){
    int inputlength = input.size();
    int RequiredPadding = (AES_BLOCK_SIZE - (inputlength % AES_BLOCK_SIZE));
    unsigned char *plain_data = (unsigned char *) (input.data());
    unsigned char enc_out[inputlength + RequiredPadding];
    memset(enc_out, 0, sizeof(enc_out));
    
    unsigned char key1[32];
    unsigned char iv1[32];
    
    for(int i = 0; i < KEYSIZE; i++){
      key1[i] = _key[i];
    }
    for(int i = 0; i < KEYSIZE; i++){
      iv1[i] = _iv[i];
    }
    
    AES_KEY enc_key;
    AES_set_encrypt_key(key1, KEYLENGTH, &enc_key);
    const size_t encslength = ((inputlength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    
    AES_cbc_encrypt(plain_data, enc_out, encslength, &enc_key, iv1, AES_ENCRYPT);
    
    auto base64string = base64::encode(enc_out, sizeof(enc_out));
    return base64string;
  }

// obfuscates key and iv twice 
std::string xor_char(unsigned char *input){
  
    int key = 128;
    for(int i = 0; i < KEYSIZE; i++){
      input[i] = input[i] ^ key;
    }
    for(int i = 0; i < KEYSIZE; i++){
      input[i] = input[i] ^ key - 27;
    }

    std::string output = base64::encode(input, KEYSIZE);
  
    return output;
  }

// creates header file for encrypted strings
  void erb_h(){
    std::ofstream outputFile("/Users/Thompson/Documents/Helios/active_secret/src/strings.h");
    
    if(outputFile.is_open()){
        outputFile<<"#pragma once"<<std::endl
                  <<"#include <string>"<<std::endl
                  << std::endl;
        for(auto x = hashtable.begin(); x != hashtable.end(); ++x ){
           outputFile<<"extern std::string const " << x->first << ";" << std::endl;
        }
        outputFile<<"extern std::string const key;" << std::endl;
        outputFile<<"extern std::string const iv;" << std::endl;
      
        outputFile.close();
    }else{
      std::cout << "could not create file";
    }
  }
  // creates cpp file for encrypted strings
  void erb_cpp(){
    std::ofstream outputFile("/Users/Thompson/Documents/Helios/active_secret/src/strings.cpp");
    
    if(outputFile.is_open()){
        outputFile<<"#include \"strings.h\""<<std::endl
                  << std::endl;
        for(auto x = hashtable.begin(); x != hashtable.end(); ++x ){
           outputFile<<"std::string const " << x->first << " = \"" << x->second << "\";" << std::endl;
        }
      
        outputFile << "std::string const key = \"" << xor_char(_key) << "\";" <<  std::endl;
        outputFile<< "std::string const iv = \"" << xor_char(_iv) << "\";" <<  std::endl;
      
        outputFile.close();
    }else{
      std::cout << "could not create file";
    }
  }

  //reads txt file with strings to encrypt
  void readfile(){
    std::ifstream inputFile;
    inputFile.open("/Users/Thompson/documents/Helios/active_secret/config/secrets.txt");
    
    if(inputFile.is_open()){
      gen_key();
      gen_iv();
      std::string line;
      std::string delimiter = ":";
      while(getline(inputFile, line)){
        std::string key = line.substr(0, line.find(delimiter));
        std::string value = line.substr(line.find(delimiter) + 2);
        std::string enc_value = encrypt(value);
        hashtable.emplace(key, enc_value);
      }
      erb_h();
      erb_cpp();
    }else{
      std::cout << "could not open file";
    }
  }

int main() {
  readfile();
  return 0;
}

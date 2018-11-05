* Hex-Encryptor

C++ library to encode data

This is a work in progress. It takes a txt file of strings that are things you do now want to show up in the binary file. This library takes those and encrypts them using openssl aes 256. They will then be encrypted in the binary file of the library. This way noboby can just view all those hardcoded secrets in your app. I currently have a few different encryption/decryption options i am working through. I also am working on a getting a ruby version so you can just add the ruby script to your build process. The other way is all c++ and it needs to be added to your project via cmake.

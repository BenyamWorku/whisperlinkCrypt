#pragma once

#include <sodium.h>
#include <string>
#include <vector>

class Encryption {
private:
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    uint64_t message_counter;

public:
    // Constructor: Initializes libsodium and generates key/nonce
    Encryption();

    // Encrypts a given message using AES and returns the encrypted message
    std::vector<unsigned char> encrypt_message(const std::string &message);

    // Decrypts a given encrypted message using AES and returns the decrypted plain text
    std::string decrypt_message(const std::vector<unsigned char> &ciphertext);
};
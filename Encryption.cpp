#include "Encryption.h"
#include <iostream>
#include <string.h>

// Constructor: Initializes libsodium and generates key/nonce
Encryption::Encryption():message_counter(0) {
    // Initialize sodium library
    if (sodium_init() == -1) {
        std::cerr << "Failed to initialize libsodium!" << std::endl;
        exit(1);
    }

    // Generate a random key and nonce
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);
}

// Encrypts a given message using AES and returns the encrypted message
std::vector<unsigned char> Encryption::encrypt_message(const std::string &message) {
    std::vector<unsigned char> ciphertext(crypto_secretbox_MACBYTES + message.size() + sizeof(message_counter));
    
    // Include message counter in ciphertext
    memcpy(ciphertext.data(), &message_counter, sizeof(message_counter));
    
    // Use a unique nonce for each message by XORing the original nonce with the message counter
    unsigned char unique_nonce[crypto_secretbox_NONCEBYTES];
    memcpy(unique_nonce, nonce, crypto_secretbox_NONCEBYTES);
    sodium_add(unique_nonce, (unsigned char*)&message_counter, sizeof(message_counter));

    // Encrypt the message
    crypto_secretbox_easy(ciphertext.data() + sizeof(message_counter), 
                          reinterpret_cast<const unsigned char *>(message.c_str()), 
                          message.size(), unique_nonce, key);

    // Increment the message counter for the next message
    message_counter++;

    return ciphertext;
}

// Decrypts a given encrypted message using AES and returns the decrypted plain text
std::string Encryption::decrypt_message(const std::vector<unsigned char> &ciphertext) {
    if (ciphertext.size() < sizeof(message_counter) + crypto_secretbox_MACBYTES) {
        std::cerr << "Invalid ciphertext size" << std::endl;
        return "";
    }

    uint64_t received_counter;
    memcpy(&received_counter, ciphertext.data(), sizeof(received_counter));

    // Reconstruct the nonce used for this message
    unsigned char unique_nonce[crypto_secretbox_NONCEBYTES];
    memcpy(unique_nonce, nonce, crypto_secretbox_NONCEBYTES);
    sodium_add(unique_nonce, (unsigned char*)&received_counter, sizeof(received_counter));

    std::vector<unsigned char> decrypted_message(ciphertext.size() - crypto_secretbox_MACBYTES - sizeof(message_counter));

    if (crypto_secretbox_open_easy(decrypted_message.data(), 
                                   ciphertext.data() + sizeof(message_counter), 
                                   ciphertext.size() - sizeof(message_counter), 
                                   unique_nonce, key) != 0) {
        std::cerr << "Decryption failed!" << std::endl;
        return "";
    }

    return std::string(decrypted_message.begin(), decrypted_message.end());
}

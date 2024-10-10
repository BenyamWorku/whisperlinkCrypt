#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <netinet/in.h> // For sockaddr_in
#include "Encryption.h" // Include the Encryption class for handling encryption

class Peer {
private:
    std::string name;          // Name of the local peer
    std::string peer_name;     // Name of the remote peer
    std::string local_ip;      // Local peer's IP address
    int udp_sock;              // UDP socket for peer discovery
    int connection_sock;       // Socket for connection with the remote peer
    int listening_sock;        // Socket for listening to incoming connections
    int tcp_port;               // intiaal TCP socket
    std::string peer_ip;                // peer ip a.o.t. local
    int peer_port;              // peer port a.o.t local
    // Encryption object for handling message encryption and decryption
    Encryption encryption;
    void cleanup();
    // Internal helper methods for networking
    std::string get_local_ip();    // Retrieve the local IP address
    void display_message(const std::string &message, bool is_local);
public:
    // Constructor
    Peer(const std::string &local_name);
    //destructor
    ~Peer();

    // Methods for peer discovery and communication
    void initialize_listener();    // Initialize the listener socket
    void broadcast_presence();     // Broadcast presence to other peers
    bool discover_peers();         // Discover available peers on the network
    bool establish_connection();   // Establish connection with a discovered peer
    bool exchange_names();         // Exchange names with the connected peer
    //bool exchange_aes_key();       // Exchange AES keys for encryption using libsodium

    // Chat session
    void handle_chat_session();    // Handle encrypted chat session
};
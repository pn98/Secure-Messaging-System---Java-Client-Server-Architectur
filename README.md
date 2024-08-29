Overview

This project is a client-server messaging application that implements secure message transmission using RSA encryption. The system allows clients to send encrypted messages to each other via a server, which handles message storage and forwarding. The application ensures the confidentiality and integrity of messages using public-key cryptography.

Prerequisites

Java Development Kit (JDK): Ensure that JDK is installed on your system. The application is written in Java.
RSA Key Pair: Each client and the server must have an RSA key pair (public and private keys). The public keys should be shared with others, while the private keys must be kept secret.
Directory Structure: Keys must be stored in a directory named Keys. The server's keys should be named server.pub (public key) and server.prv (private key). Clients should have their keys named as userid.pub and userid.prv (e.g., alice.pub and alice.prv).
Files

Client.java
This file contains the client-side application logic. It connects to the server, authenticates the user, receives any pending messages, and allows the user to send a new message.

Key Features:

User Authentication: The user ID is hashed and sent to the server for authentication.
Message Reception: The client receives and decrypts any messages intended for it.
Message Sending: Users can send encrypted messages to other users via the server.
Encryption: Messages are encrypted using the server's public key before being sent.
Server.java
This file contains the server-side application logic. It listens for incoming client connections, authenticates clients, forwards messages, and stores messages securely.

Key Features:

Client Authentication: Authenticates clients by receiving a hashed user ID.
Message Forwarding: Receives messages from clients, re-encrypts them with the recipient's public key, and stores them securely.
Message Storage: Messages are stored in a HashMap using the recipient's hashed user ID as the key.





Improvements to be made 

* user with wrong private key can send message successfully

* signature code present but never called

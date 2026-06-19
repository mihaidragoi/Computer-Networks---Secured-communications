# Secured Network Communications Simulation 🔒

## 📖 Overview
This repository contains a C# project developed for a Computer Networks course, focusing on network security and encrypted data transmission. The simulation demonstrates how two endpoints (Client and Server) can securely exchange data over a TCP connection by establishing a shared secret and encrypting the communication channel.

## 🧩 Architecture & Project Structure
The project integrates cryptographic algorithms with network programming. The core components include:

*   **`DiffieHellman.cs`**: Implements the **Diffie-Hellman key exchange** protocol. This allows the client and server to securely agree on a shared cryptographic key over a potentially insecure channel without transmitting the key itself.
*   **`CryptService.cs`**: Handles the encryption and decryption processes for the data payloads, utilizing the shared key established by the Diffie-Hellman algorithm to maintain data confidentiality.
*   **`SecurePacket.cs`**: Defines the structure of the data packets transmitted across the network, ensuring that the payload is securely encapsulated.
*   **`MyTcpClient.cs` & `MyTcpServer.cs`**: Represent the network endpoints. They handle the TCP connection lifecycle, initiate the key exchange process upon connection, and use the `CryptService` to send and receive encrypted messages.
*   **`Program.cs`**: The main entry point that initializes the secure server and client, demonstrating the secure handshake and subsequent encrypted data transfer.

## 🛠️ Technologies & Concepts
*   **Language:** C#
*   **Core Concepts:** Network Security, Cryptography, Diffie-Hellman Key Exchange, Data Encryption/Decryption, TCP Client-Server Architecture, Secure Data Encapsulation.

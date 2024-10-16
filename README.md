Secure Chat System
Hi, I’m Irtaza, and today I’m sharing a Secure Chat System that I’ve developed as part of my Cyber Security assignment. 
This assignment focuses on building a secure communication platform between a client and a server using C++. The main objective 
was to ensure that messages exchanged between the client and server are encrypted and secure.

Overview
This system is designed to protect communication by encrypting messages and securely handling user credentials. The key features of this assignment are:

User Registration:
Users can sign up with a unique username and password.
Passwords are hashed using a secure hashing algorithm and stored securely to avoid saving them in plain text.

User Authentication:
During login, the system authenticates users by checking their hashed passwords against the stored credentials.

Encrypted Messaging:
Once logged in, users can engage in secure communication with the server. Messages are encrypted before being sent, ensuring that 
no unauthorized party can access the conversation.

Secure Credential Storage:
User credentials, such as the username and hashed password, are securely stored to maintain confidentiality and integrity.

Implementation
The code for this assignment is written in C++ and consists of two files: server.cpp and client.cpp. The code has been tested on Linux, and 
it should work seamlessly in that environment. If you're planning to run it on Windows, please ensure that the necessary libraries for 
encryption and decryption are installed first.

Testing and Results
While testing the application, I monitored the network traffic using Wireshark, and I observed that all data was encrypted, confirming that 
the system works well. This assignment has many areas that can be improved or modified in the future, but I made sure to complete it before my deadline.

This assignment demonstrates the importance of security in digital communication and how encryption techniques can be used to protect sensitive information.

#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>      // using for socket creation communication, send rec functions 
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>      // is gives functions for converting IP addresses between text and binary forms
#include <openssl/aes.h>    // using for functions like AES encryption and decryption
#include <openssl/rand.h>   // using for generating key generation
#include <openssl/evp.h>    // using for functions like AES encryption and decryption
#include <iomanip>          // for alingment like for using setw etc 

using namespace std;

int sock;  
const int serverport = 5051;


string AES_encrypt(const string& plaintext, const string& key) 
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char ciphertext[1024];
    int len, ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        cerr << endl << "Error Creating Context" << endl;
        exit(EXIT_FAILURE);
    }

    // Generate a random IV
    if (!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) 
    {
        cerr << endl << "Error Generating IV" << endl;
        exit(EXIT_FAILURE);
    }

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key.c_str(), iv)) 
    {
        cerr << endl  << "Error Initializing Encryption" << endl;
        exit(EXIT_FAILURE);
    }

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.c_str(), plaintext.length())) 
    {
        cerr << endl << "Error During Encryption" << endl;
        exit(EXIT_FAILURE);
    }
    ciphertext_len = len;

    // Finalize the encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    {
        cerr << endl << "Error During Final Encryption Step" << endl;
        exit(EXIT_FAILURE);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Return ciphertext as a hex string (IV + ciphertext)
    stringstream ss;
    for (int i = 0; i < EVP_MAX_IV_LENGTH; i++) 
    {
        ss << hex << setw(2) << setfill('0') << (int)iv[i];
    }
    for (int i = 0; i < ciphertext_len; i++) 
    {
        ss << hex << setw(2) << setfill('0') << (int)ciphertext[i];
    }

    return ss.str();
}

string AES_decrypt(const string& ciphertext, const string& key) 
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char decryptedtext[1024];
    int len, decryptedtext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        cerr << endl << "Error Creating Context" << endl;
        exit(EXIT_FAILURE);
    }

    // Extract the IV from the ciphertext (first block)
    for (int i = 0; i < EVP_MAX_IV_LENGTH; i++) 
    {
        iv[i] = stoi(ciphertext.substr(i * 2, 2), nullptr, 16);
    }

    // Initialize the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key.c_str(), iv)) 
    {
        cerr << endl << "Error Initializing Decryption" << endl;
        exit(EXIT_FAILURE);
    }

    // Convert ciphertext hex string back to bytes
    int ciphertext_len = (ciphertext.length() - EVP_MAX_IV_LENGTH * 2) / 2;
    unsigned char raw_ciphertext[1024];
    for (int i = 0; i < ciphertext_len; i++) 
    {
        raw_ciphertext[i] = stoi(ciphertext.substr(EVP_MAX_IV_LENGTH * 2 + i * 2, 2), nullptr, 16);
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, raw_ciphertext, ciphertext_len)) 
    {
        cerr << endl << "Error During Decryption" << endl;
        exit(EXIT_FAILURE);
    }
    decryptedtext_len = len;

    // Finalize the decryption.
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) 
    {
        cerr << endl << "Error During Final Decryption Step" << endl;
        exit(EXIT_FAILURE);
    }
    decryptedtext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)decryptedtext, decryptedtext_len);
}


void create_socket() 
{
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
    {
        cerr << endl << "Failed To Create Socket!" << endl;
        exit(EXIT_FAILURE);  
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));  
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(serverport);  
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");  

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) 
    {
        cerr << endl << "Failed To Connect To Server!" << endl;
        exit(EXIT_FAILURE);  
    }

    cout << endl << "Connected To The Server Successfully!" << endl;
}


void chat(int client_socket) 
{
    string aes_key = "1234567890123456"; 
    char buffer[1024] = {0};
    
    while (true) 
    {
        memset(buffer, 0, sizeof(buffer));

        cout << endl << "Enter Message (Type 'bye' To Exit) : ";
        string message;
        getline(cin, message);

        string encrypted_message = AES_encrypt(message, aes_key);
        send(client_socket, encrypted_message.c_str(), encrypted_message.size(), 0);

        if (message == "bye") 
        {
            cout << endl << "Chat Ended By You.\n";
            exit(0);
        }

        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) 
        {
            cerr << endl << "Failed To Receive Response From Server Side" << endl;
            break;
        } 
        else 
        {
            string received_message(buffer);
            string decrypted_message = AES_decrypt(received_message, aes_key);
            cout << endl << "Server: " << decrypted_message << endl;
        }
    }
}


void registeruser(int client_socket) 
{
    string aes_key = "1234567890123456"; 
    string email;
    string name;
    string pass;

    cout << endl << "Enter Email Here Without Adding (@gmail.com) ---> ";
    getline(cin, email);
    email += "@gmail.com";  
    cout << endl << "Enter UserName Here ---> ";
    getline(cin, name);
    cout << endl << "Enter Password Here ---> ";
    getline(cin, pass);
    
    string registrationdata = email + "," + name + "," + pass;

    string encrypted_registration = AES_encrypt(registrationdata, aes_key);
    int command = 1; 
    ssize_t command_sent = send(client_socket, &command, sizeof(command), 0);


    if (command_sent < 0) 
    {
        cerr << endl << "Failed To Send Command To The Server!" << endl;
        return;  
    }

    


    ssize_t bytes_sent = send(client_socket, encrypted_registration.c_str(), encrypted_registration.size(), 0);

    if (bytes_sent < 0) 
    {
        cerr << endl << "Failed To Send Registration Data To Server!" << endl;
        return;  
    } 
    else 
    {
        cout << endl << "Registration Data Sent Successfully!" << endl;
    }

    char buffer[1024] = {0};
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);

    if (bytes_received < 0) 
    {
        cerr << endl << "Failed To Receive Response From The Server!" << endl;
    } 
    else 
    {
        cout << endl << "Server Response ---> " << buffer << endl;
    }
}


void login(int client_socket) 
{
    string aes_key = "1234567890123456"; 
    string username;
    string password;

    cout << endl << "Enter Username Here ---> ";
    getline(cin, username);
    cout << endl << "Enter Password Here ---> ";
    getline(cin, password);

    string loginData = username + "," + password;

    string encrypted_loginData = AES_encrypt(loginData, aes_key);
    int command = 2; 
    ssize_t command_sent = send(client_socket, &command, sizeof(command), 0);

    if (command_sent < 0) 
    {
        cerr << endl << "Failed To Send Command To The Server!" << endl;
        return;  
    }

    

    ssize_t bytes_sent = send(client_socket, encrypted_loginData.c_str(), encrypted_loginData.size(), 0);

    if (bytes_sent < 0) 
    {
        cerr << endl << "Failed To Send Login Data To Server!" << endl;
        return;  
    } 
    else 
    {
        cout << endl << "Login Info Sent Successfully" << endl;
    }

    char buffer[1024] = {0};
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);

    if (bytes_received < 0) 
    {
        cerr << endl << "Failed To Receive Response From The Server!" << endl;
    } 
    else 
    {
        // Ensure buffer is null-terminated for comparison
        buffer[bytes_received] = '\0'; // Null-terminate the received string

        // Check if the login was successful
        if (strcmp(buffer, "Login Successful") == 0) 
        {
            cout  << endl  << "Server Response ---> " << buffer << endl;
            chat(client_socket);
        } 
        else 
        {
            cout << endl << "Server Response ---> " << buffer << endl;
            cout << "Invalid credentials! Please try again." << endl;
            return;  // Return to the main menu
        }
    }
}




int main() 
{       
        cout << endl << endl;
        cout<< "\t\t   --------------------------------------------------------------------------------------------------------------------------------------------------\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |       ░▒█░░▒█░█▀▀░█░░█▀▄░▄▀▀▄░█▀▄▀█░█▀▀░ ░░▀▀█▀▀░▄▀▀▄░░ ░▒█▀▀▀█░█▀▀░█▀▄░█░▒█░█▀▀▄░█▀▀░ ░▒█▀▀▄░█░░░░█▀▀▄░▀█▀░░ ░▒█▀▀▀█░█░░█░█▀▀░▀█▀░█▀▀░█▀▄▀█   |\n"
            << "\t\t   |       ░▒█▒█▒█░█▀▀░█░░█░░░█░░█░█░▀░█░█▀▀░ ░░░▒█░░░█░░█░░ ░░▀▀▀▄▄░█▀▀░█░░░█░▒█░█▄▄▀░█▀▀░ ░░▒█░░░░█▀▀█░█▄▄█░░█░░ ░░░▀▀▀▄▄░█▄▄█░▀▀▄░░█░░█▀▀░█░▀░█  |\n"
            << "\t\t   |       ░▒▀▄▀▄▀░▀▀▀░▀▀░▀▀▀░░▀▀░░▀░░▒▀░▀▀▀░ ░░▒█░░░░▀▀░░░░ ▒█▄▄▄█░▀▀▀░▀▀▀░░▀▀▀░▀░▀▀░▀▀▀░░ ░▒█▄▄▀░▀░░▀░▀░░▀░░▀░░░ ░▒█▄▄▄█░▄▄▄▀░▀▀▀░░▀░░▀▀▀░▀░░▒▀   |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"  
            << "\t\t   |                                          ___  ____  ____  _  _  ____  ____      ___  ____  ____   ____                                         |\n"
            << "\t\t   |                                         / __)(  )  (_  _)( ___)( \\( )(_  _)    / __)(_  _)(  _ \\ ( ___)                                        |\n"
            << "\t\t   |                                        ( (__  )(__  _)(_  )__)  )  (   )(      \\__ \\ _)(_  )(_) ) )__)                                         |\n"
            << "\t\t   |                                         \\___)(____)(____)(____)(_)\\_) (__)     (___/(____)(____/ (____)                                        |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   --------------------------------------------------------------------------------------------------------------------------------------------------\n";  
        
        cout << endl << endl;
    
    
    
    create_socket();

    while (true) 
    {
        cout << endl << "\nPlease Select One Option To Proceed\n\n";
        cout << "1. Register\n";
        cout << "2. Login\n";
        cout << "3. Exit\n";
        cout << endl << "Enter Your Choice Here ---> ";

        int choice;
        cin >> choice;

        while (cin.fail() || choice < 1 || choice > 3) 
        {
            cout << endl << "Invalid Option Selected. Please Enter 1, 2, Or 3 To Proceed";
            cin.clear(); 
            cin.ignore(); 
            cin >> choice; 
        }

        cin.ignore();  

        switch (choice) 
        {
            case 1: 
            {
                registeruser(sock);
                break;
            }
            case 2: 
            {
                login(sock);
                // chat(sock);
                break;
            }
            case 3: 
            {
                cout << endl << "Exiting Chat System\n";
                close(sock);  
                return 0;
            }
        }
    }

    close(sock);  
    return 0;
}
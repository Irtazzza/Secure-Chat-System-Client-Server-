#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstdlib> 

using namespace std;

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
        cerr << endl << "Error creating context" << endl;
        exit(EXIT_FAILURE);
    }

    // Generate a random IV
    if (!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) 
    {
        cerr << endl << "Error generating IV" << endl;
        exit(EXIT_FAILURE);
    }

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char *)key.c_str(), iv)) 
    {
        cerr << endl << "Error initializing encryption" << endl;
        exit(EXIT_FAILURE);
    }

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.c_str(), plaintext.length())) 
    {
        cerr << endl << "Error during encryption" << endl;
        exit(EXIT_FAILURE);
    }
    ciphertext_len = len;

    // Finalize the encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
    {
        cerr << endl << "Error during final encryption step" << endl;
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
        cerr << endl << "Error creating context" << endl;
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
        cerr << endl << "Error initializing decryption" << endl;
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
        cerr << endl << "Error during decryption" << endl;
        exit(EXIT_FAILURE);
    }
    decryptedtext_len = len;

    // Finalize the decryption.
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) 
    {
        cerr << endl << "Error during final decryption step" << endl;
        exit(EXIT_FAILURE);
    }
    decryptedtext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char *)decryptedtext, decryptedtext_len);
}


string sha256(const string& str) 
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}


void handlechat(int client_socket) 
{
    string aes_key = "1234567890123456"; 
    char buffer[1024] = {0};
    
    while (true) 
    {
        memset(buffer, 0, sizeof(buffer));

        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) 
        {
            cout << endl << "Client Disconnected.\n";
            break;
        }

        string received_message(buffer);
        string decrypted_message = AES_decrypt(received_message, aes_key);
        cout << endl << "Client: " << decrypted_message << endl;

        if (decrypted_message == "bye") 
        {
            cout << endl << "Chat Ended By Client.\n";
            // break;
            close(client_socket); 
            exit(EXIT_SUCCESS); // Exit the entire program
        }

        cout << endl << "Enter Your Message To The Client: ";
        string response;
        getline(cin, response);

        string encrypted_response = AES_encrypt(response, aes_key);
        send(client_socket, encrypted_response.c_str(), encrypted_response.size(), 0);

        // if (response == "bye") 
        // {
        //     cout << endl << "Chat Ended By Server\n";
        //     break;
        // }
    }

    close(client_socket);
}



void handleregistration(int client_socket) 
{
    string aes_key = "1234567890123456";  
    char buffer[1024] = {0};


    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) 
    {
        cerr << endl << "Failed To Receive Data From Client" << endl;
        return;
    }

    cout << endl << "Registration Data Received\n";


    string encrypted_data(buffer, bytes_received);
    string decrypted_data = AES_decrypt(encrypted_data, aes_key);


    string email, username, password;
    stringstream ss(decrypted_data);
    getline(ss, email, ',');
    getline(ss, username, ',');
    getline(ss, password, ',');


    ifstream credfile("cred.txt");
    string line;
    bool exists = false;

    while (getline(credfile, line)) 
    {
        stringstream stored(line);
        string stored_username, stored_email, stored_password;
        getline(stored, stored_username, ',');
        getline(stored, stored_password, ',');  
        getline(stored, stored_email, ',');     

        if (email == stored_email || username == stored_username) 
        {
            exists = true;
            break;
        }
    }
    credfile.close();

    if (exists) 
    {
        string response = "Registration Failed: Choose Unique Username And Email";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }

    
    string mysalt = "hiiamirtaza";  
    string saltedpassword = mysalt + password;
    string hashedpassword = sha256(saltedpassword);  

    
    ofstream outFile("cred.txt", ios::app);
    if (outFile.is_open()) 
    {
        outFile << username << "," << hashedpassword << "," << email << endl;
        outFile.close();

        string success_msg = "Registration Successful!";
        send(client_socket, success_msg.c_str(), success_msg.size(), 0);
    } 
    else 
    {
        cerr << endl << "Error In Opening File" << endl;
        string failmsg = "Registration Failed Due To Server Error";
        send(client_socket, failmsg.c_str(), failmsg.size(), 0);
    }
}


void handlelogin(int client_socket) 
{
    string mysalt = "hiiamirtaza";  
    char buffer[1024] = {0};
    string aes_key = "1234567890123456";  

    
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) 
    {
        cerr << "Failed To Receive Login Data From Client!" << endl;
        return;
    }

    cout << endl << "Login Data Received, Now Checking Please Wait...\n";

    
    string encrypted_login_data(buffer, bytes_received);
    string login_data = AES_decrypt(encrypted_login_data, aes_key); 

    
    size_t delimiter_pos = login_data.find(',');

    if (delimiter_pos == string::npos) 
    {
        cerr << endl << "Invalid Login Data Received" << endl;
        string response = "Invalid Login Data Format.";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }


    string username = login_data.substr(0, delimiter_pos);
    string password = login_data.substr(delimiter_pos + 1);


    string salted_password = mysalt + password;
    

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted_password.c_str(), salted_password.size(), hash);


    string hashed_password;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) 
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        hashed_password += hex;
    }

  
    ifstream infile("cred.txt");
    string line;
    bool login_success = false;

    while (getline(infile, line)) 
    {
        size_t comma_pos1 = line.find(',');
        size_t comma_pos2 = line.find(',', comma_pos1 + 1);

        if (comma_pos1 == string::npos || comma_pos2 == string::npos) 
        {
            cerr << endl << "Invalid Credential Format in File: " << line << endl;
            continue; 
        }


        string stored_username = line.substr(0, comma_pos1);
        string stored_password = line.substr(comma_pos1 + 1, comma_pos2 - comma_pos1 - 1);


        if (username == stored_username && hashed_password == stored_password) 
        {
            login_success = true;
            break;
        }
    }
    infile.close();

    if (login_success) 
    {
        string response = "Login Successful";
        send(client_socket, response.c_str(), response.size(), 0);
    } 
    else 
    {
        string response = "Login Failed! Invalid Username or Password.";
        send(client_socket, response.c_str(), response.size(), 0);
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
            << "\t\t   |                                              ___  ____  ____  _  _  ____  ____      ___  ____  ____   ____                                     |\n"
            << "\t\t   |                                             / __)( ___)(  _ \\( \\/ )( ___)(  _ \\    / __)(_  _)(  _ \\ ( ___)                                    |\n"
            << "\t\t   |                                             \\__ \\ )__)  )   / \\  /  )__)  )   /    \\__ \\ _)(_  )(_) ) )__)                                     |\n"
            << "\t\t   |                                             (___/(____)(_)\\_)  \\/  (____)(_)\\_)    (___/(____)(____/ (____)                                    |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   |                                                                                                                                                |\n"
            << "\t\t   --------------------------------------------------------------------------------------------------------------------------------------------------\n";

        cout << endl << endl;  

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(serverport);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address));
    listen(server_socket, 5);

    while (1) 
    {
        int client_socket = accept(server_socket, NULL, NULL);
        pid_t new_pid = fork();
        if (new_pid == -1) 
        {
            cout << endl << "Error, Unable To Fork Process\n";
        } 
        else if (new_pid == 0) 
        {
            while (true) 
            {
                int command;

                ssize_t command_received = recv(client_socket, &command, sizeof(command), 0);
                if (command_received <= 0) 
                {
                    cout << endl << "Client Disconnected.\n";
                    break;
                }

                if (command == 3) 
                { 
                    cout << endl << "Client Disconnected.\n";
                    break;
                } 
                else if (command == 1) 
                { 
                    cout << endl << "Handling Registration For Client...\n";
                    handleregistration(client_socket);
                } 
                else if (command == 2) 
                { 
                    cout << endl << "Handling Login For Client...\n";
                    handlelogin(client_socket);
                    handlechat(client_socket); 
                } 
                else 
                {
                    cout << endl << "Unknown Command Received From Client\n";
                }
            }

            close(client_socket);
            exit(0);
        } 
        else 
        {
            close(client_socket);
        }
    }

    close(server_socket);
    return 0;
}
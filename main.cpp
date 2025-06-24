#include <iostream>
#include <sstream>
// sqlite for storage, sqlite3
#include <sqlite3.h>
// bcrypt for password hashing https://github.com/trusch/libbcrypt
#include <bcrypt/BCrypt.hpp>
// openssl for password encrypting and decrypting stored passwords, libssl-dev
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

//function declarations
void startMenu();
void authenticatedMenu();
void login();
void signUp();
void initDB();
void createUsersTable();
void getPasswords();
void setPassword();
void removePassword();
void createPasswordsTable();
void createUser(string username, string password);
void authenticateUser(string username, string password);
string decrypt(const string& ciphertext, const unsigned char* key, const unsigned char* iv);
string encrypt(const string& plaintext, const unsigned char* key, const unsigned char* iv);

//globals
sqlite3* db;
const char * dbfile = "db";
string username;
// Key and IV should be securely generated in a real application
unsigned char key[EVP_MAX_KEY_LENGTH] = "01234567890123456789012345678901";  // 256-bit key for AES-256
unsigned char iv[17] = "0123456789abcdef";  // 128-bit IV

int main(int argc, char ** argv){
    try{
        initDB();
        startMenu();
        authenticatedMenu();
    }catch(string e){
        cerr << "ERROR: " << e << endl;
    }
    sqlite3_close(db);
    return 0;
}

void startMenu(){
    cout << "Choose one of the following options:\n"
         << "1 - Login\n"
         << "2 - Register\n"
         << "-> " << flush;
    int n;
    cin >> n;
    cout << "Your choice: " << n << endl;
    switch(n){
        case 1: login(); break;
        case 2: signUp(); break;
        default: throw(string("Invalid Input"));
    }
}

void authenticatedMenu(){
    cout << "Choose one of the following options:\n"
         << "1 - Retrieve Passwords\n"
         << "2 - Store New Password\n"
         << "3 - Remove Password\n"
         << "4 - Quit\n"
         << "-> " << flush;
    int n;
    cin >> n;
    cout << "Your choice: " << n << endl;
    switch(n){
        case 1: getPasswords(); break;
        case 2: setPassword(); break;
        case 3: removePassword(); break;
        case 4: return;
        default: throw(string("Invalid Input"));
    }
    authenticatedMenu();
}

void initDB(){
    int err = sqlite3_open(dbfile, &db);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database could not be opened \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }
    createUsersTable();
    createPasswordsTable();
}

void createUsersTable(){
    const char* sql = "CREATE TABLE IF NOT EXISTS USERS("
                "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                "USERNAME TEXT NOT NULL UNIQUE,"
                "HASHED_PASSWORD TEXT NOT NULL)";
    int err = sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database could not create table 'Users' \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }
}

void setPassword(){
    //prompt
    string tag;
    string credentialName;
    string password;
    string encryptedPassword;

    cout << "Enter name tag for this credential(eg. GMail):\n"
         << "-> " << flush;
    cin >> tag;

    cout << "Enter name for this credential(eg. myemail@email.com):\n"
         << "-> " << flush;
    cin >> credentialName;

    cout << "Enter the password for this credential:\n"
         << "-> " << flush;
    cin >> password;

    encryptedPassword = encrypt(password, key, iv);

    //database
    const char * sql = "INSERT INTO passwords (username, tag, credentialName, encryptedpassword) VALUES (?,?,?,?)";
    sqlite3_stmt * stmt;
    int err = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to prepare statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 2, tag.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 3, credentialName.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_blob(stmt, 4, encryptedPassword.data(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    err = sqlite3_step(stmt);
    if(err != SQLITE_DONE){
        stringstream ss;
        ss << "Database could not create new user \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_finalize(stmt);

}

void removePassword(){
    int id;

    //prompts
    cout << "Enter the id number of the password for deletion:\n"
         << "-> " << flush;
    cin >> id;

    //database
    const char* sql = "DELETE FROM passwords WHERE username=? AND id=?";
    sqlite3_stmt * stmt;
    int err = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to prepare statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_int(stmt, 2, id);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    err = sqlite3_step(stmt);
    if(err != SQLITE_DONE){
        stringstream ss;
        ss << "Database could not delete password \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_finalize(stmt);

}

void getPasswords(){
    const char* sql = "SELECT * FROM passwords WHERE username=?";
    sqlite3_stmt * stmt;
    int err = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to prepare statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    while(sqlite3_step(stmt) == SQLITE_ROW){
        int id = sqlite3_column_int(stmt, 0);
        string tag = string(reinterpret_cast< const char* >(sqlite3_column_text(stmt, 2)));
        string credentialName = string(reinterpret_cast< const char* >(sqlite3_column_text(stmt, 3)));
        string encrypted = string(reinterpret_cast< const char* >(sqlite3_column_blob(stmt, 4)));
        auto decryptedPassword = decrypt(encrypted, key, iv);
        cout << id << " " << tag << " " << credentialName << " " << decryptedPassword << endl;
    }

    sqlite3_finalize(stmt);

}

void createUser(string username, string password){
    string hash = BCrypt::generateHash(password);

    const char * sql = "INSERT INTO USERS (USERNAME, HASHED_PASSWORD) VALUES (?,?)";
    sqlite3_stmt * stmt;
    int err = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to prepare statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    err = sqlite3_step(stmt);
    if(err != SQLITE_DONE){
        stringstream ss;
        ss << "Database could not create new user \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_finalize(stmt);
    ::username = username;
}

void authenticateUser(string username, string password){
    string hash;

    //get user and its hash from database
    const char * sql = "SELECT * from USERS where username=?";
    sqlite3_stmt * stmt;
    int err = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to prepare statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database failed to bind statement \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    err = sqlite3_step(stmt);
    if(err != SQLITE_ROW){
        stringstream ss;
        ss << "Database could not get user \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }

    username = string(reinterpret_cast< const char* >(sqlite3_column_text(stmt, 1)));
    hash = string(reinterpret_cast< const char* >(sqlite3_column_text(stmt, 2)));
    sqlite3_finalize(stmt);

    //compare the password and the db hash
    bool authenticated = BCrypt::validatePassword(password,hash);
    cout << authenticated << endl;
    ::username = username;
}

void signUp(){
    string username;
    string password;
    string hash;

    //prompts
    cout << "Choose a username\n"
         << "-> " << flush;
    cin >> username;
    cout << "Choose a password\n"
         << "-> " << flush;
    cin >> password;

    createUser(username, password);
    return;
}

void login(){
    string username;
    string password;
    string hash;

    //prompts
    cout << "Enter a username\n"
         << "-> " << flush;
    cin >> username;
    cout << "Enter a password\n"
         << "-> " << flush;
    cin >> password;

    authenticateUser(username, password);
    return;
}


void createPasswordsTable(){
    const char* sql = "CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, tag TEXT NOT NULL, credentialname TEXT NOT NULL, encryptedpassword BLOB NOT NULL)";
    int err = sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
    if(err != SQLITE_OK){
        stringstream ss;
        ss << "Database could not create table 'Passwords' \n" << sqlite3_errmsg(db);
        throw(ss.str());
    }
}


string getOpenSSLError() {
    return string(ERR_error_string(ERR_get_error(), NULL));
}

string encrypt(const string& plaintext, const unsigned char* key,
                    const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw string("Failed to create cipher context: " + getOpenSSLError());

    int len;
    string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        throw string("EVP_EncryptInit_ex failed: " + getOpenSSLError());

    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                               reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()))
        throw string("EVP_EncryptUpdate failed: " + getOpenSSLError());
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len))
        throw string("EVP_EncryptFinal_ex failed: " + getOpenSSLError());
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

string decrypt(const string& ciphertext,
                    const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw string("Failed to create cipher context: " + getOpenSSLError());

    int len;
    string plaintext;
    plaintext.resize(ciphertext.size());

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        throw string("EVP_DecryptInit_ex failed: " + getOpenSSLError());

    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                               reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()))
        throw string("EVP_DecryptUpdate failed: " + getOpenSSLError());
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len))
        throw string("EVP_DecryptFinal_ex failed: " + getOpenSSLError());
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}


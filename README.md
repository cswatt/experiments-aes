# playing with aes in java
For Network Security, Spring 2015

## to run the program
ARGUMENTS:
```
Server [port] [mode]
Client1 [name] [port] [filename] [password] [client1's privatekey] [client2's publickey]
Client2 [name] [port] [client2's privatekey] [client1's publickey]
```

EXAMPLE:
```
java Server 6066 t
java Client1 localhost 6066 input.txt secret_shhhhhhhh private_key1.der public_key2.der
java Client2 localhost 6066 private_key2.der public_key1.der
```

## Java files (3)
* Client1.java
* Client2.java
* Server.java

## RSA key files (4)
* Client 1's public key: public_key1.der
* Client 1's private key: private_key1.der
* Client 2's public key: public_key2.der
* Client 2's private key: private_key2.der
 Keys should be in same folder as executables

 Here is how they were generated
```
$ openssl genrsa -out private_key1.pem 2048
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key1.pem \
    -out private_key1.der -nocrypt
$ openssl rsa -in private_key1.pem -pubout -outform DER -out public_key1.der

$ openssl genrsa -out private_key2.pem 2048
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key2.pem \
    -out private_key2.der -nocrypt
$ openssl rsa -in private_key2.pem -pubout -outform DER -out public_key2.der
```

## high-level overview
1. start server. on start, server is in "receiving mode"
2. client1 connects to server
3. client1 sends ciphertext (encrypted with AES), AES key (encrypted with RSA using client2's public key), initialization vector, signature (hashed plaintext encrypted with RSA using client1's private key) to server
4. server is expecting four byte arrays. once server has received this, server goes into "sending mode"
5. server sends four byte arrays. in UNTRUSTED mode, server replaces the ciphertext with its own "serverdata" file
6. client2 receives four byte arrays. client2 decrypts everything, and compares hash of plaintext to the decrypted signature.
7. if the verification fails, client 2 prints VERIFICATION FAILED. otherwise, client 2 prints VERIFICATION PASSED and saves the decrypted file as "client2data"

### Server.java
Server does a thing with threads that I honestly don't understand, but I think it works so there's that.

METHODS:
* run - actually running each thread
* loadFile - same method that exists in Client1/2, just a quick way to load a file from a String filename
* checkArgs - checks that supplied arguments are valid, namely that both port number and mode are supplied, that the port number is actually a number, and the mode is u/t/U/T

### Client1.java
Client1 is the client that encrypts and sends out files.
It uses two global variables, key and initialization_vector.

METHODS:
* checkArgs - checks that supplied arguments are valid, namely that the expected number of args were supplied (6), that the port number is actually a number, and that the password is a 16-character password that does not contain any illegal characters (as specified by assignment)
* loadFile - same method that exists in Server/Client2, just a quick way to load a file from a String filename
* AES_encrypt - encrypts with AES
* RSA_encrypt - encrypts with RSA
* SHA_256 - same method that exists in Client2, computes a hash using SHA-256
* loadPrivate - same method that exists in Client2, loads a private key from file
* loadPublic - same method that exists in Client2, loads a public key from file

### Client2.java
Client2 receives files from server, decrypts them, and verifies that the files have not been altered.

METHODS:
* checkArgs - checks that supplied arguments are valid, namely that the expected number of args were supplied (4), and the port number is actually a number.
* loadFile - same method that exists in Server/Client1, just a quick way to load a file from a String filename
* AES_decrypt - decrypts with AES
* RSA_decrypt - decrypts with RSA
* SHA_256 - same method that exists in Client1, computes a hash using SHA-256
* loadPrivate - same method that exists in Client1, loads a private key from file
* loadPublic - same method that exists in Client1, loads a public key from file
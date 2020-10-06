[![licence](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://github.com/babbadeckl/ABE-RestAPI/blob/master/LICENSE)

# Attribute Based Encryption REST API

A C++ Rest API for Attribute Based Encryption using [zeutro's openabe library](https://github.com/zeutro/openabe).
It supports Encryption, Decryption and Key Generation for Key-Policy Attribute Based Encryption (KP-ABE) as well as for Ciphertext-Policy Attribute Based Encryption (CP-ABE).

## Docker Image / Container setup

```
$ docker pull babbadeckl/abe-api:v1.4
$ docker run -p <port>:12345 -it babbadeckl/abe-api:v1.4
```

## Manual Installation

### Requirements
---
* [Microsoft's C++ REST SDK](https://github.com/microsoft/cpprestsdk)
* [OpenSSL](https://www.openssl.org/source/) (Version 1.1.1f)
* [Boost](https://www.boost.org/users/history/version_1_65_0.html) (Version 1.65+, if you want to use OpenSSL Version 1.0+)
* [Zeutro's openabe library](https://github.com/zeutro/openabe)
* [Python3](https://www.python.org/download/releases/3.0/)
  * [Requests library](https://pypi.org/project/requests/)

### Installation
---
```
$ git clone https://github.com/babbadeckl/ABE-RestAPI

$ cd ABE-RestAPI 

$ mkdir build && cd build

$ cmake ..

$ make
```

### Usage
---

To run the server execute following command in the build directory:
```
./restserver

Listening for requests at: http://127.0.0.1:12345/
Press ENTER to exit.

```
Afterwards the restserver should be running on localhost (Port 12345) (host and port can be changed in main.cpp)  
Once you've confirmed that the server is running you can test the functionality by executing the test script in the tests directory.

```
python3 ABE_API_test.py
```

If you've installed everything correctly it should output following:

```
### Testing Key-Policy ABE (KP-ABE)
	[+] Test: Key generation [PASSED]
	[+] Test: Encryption [PASSED]
	[+] Test: Successful Decryption [PASSED]
	[+] Test: Decryption with wrong attributes should fail [PASSED]

### Testing Ciphertext-Policy ABE (CP-ABE)
	[+] Test: Key generation [PASSED]
	[+] Test: Encryption [PASSED]
	[+] Test: Successful Decryption [PASSED]
	[+] Test: Decryption with wrong attributes should fail [PASSED]
```

### API Functions
---

#### Key Generation
Generates a key for a user. Depending on the used scheme, the key is either based on Policy Trees (KP-ABE) or Attribute Lists (CP-ABE) (find more info about how to specify the attribute field [in the official zeutro ABE documentation (Chapter 2.3)](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-api-doc.pdf))

```
/gen_attribute_keys
```
params:   
* `scheme` : determines the ABE scheme (either `kp` [Key-Policy ABE] or `cp` [Ciphertext-Policy ABE])
* `attribute` : 
  * Key-Policy ABE: Policy Trees (supports boolean formulas)
  * Ciphertext-Policy ABE: Attribute List (just a list of attributes seperated by \``|`\`)

Example:
* Key-Policy ABE: `gen_attribute_keys?scheme=kp&attribute=Doctor and Floor>=2`
* Ciphertext-Policy ABE: `gen_attribute_keys?scheme=cp&attribute=Doctor|Floor=2`

#### Encryption
Encrypts a specified plaintext with a certain key. For KP-ABE this key can be just a list of attributes separated by a \``|`\`. For CP-ABE it can also be a Policy Tree including boolean formulas.

```
/encrypt
```

params:  
* `scheme` : determines the ABE scheme
* `key` : 
  * KP-ABE: Attribute List
  * CP-ABE: Policy Tree
* `plaintext`: String that should be encrypted

Example:
* KP-ABE: `encrypt?scheme=kp&key=Doctor|Floor=2&plaintext=Hello World!`
* CP-ABE: `encrypt?scheme=cp&key=Doctor and Floor<=4&plaintext=Hello World!`

#### Decryption
Decrypts a specified ciphertext with the user's previously generated key. 

```
/decrypt
```

params:
* `scheme`: determines the ABE scheme
* `key`: the user's generated Key.   
***Note: KP-Keys can only be used for decrypting KP-Ciphertexts. Same counts for CP-Keys.***
* `ciphertext`: the ciphertext that should be decrypted

Example:
* KP-ABE: `decrypt?scheme=kp&key=<YOUR KEY HERE>&ciphertext=<CIPHERTEXT HERE>`
* CP-ABE: `decrypt?scheme=cp&key=<YOUR KEY HERE>&ciphertext=<CIPHERTEXT HERE>`

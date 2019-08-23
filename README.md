# CURRENTLY IN DEVELOPMENT - SEVERAL BUGS ARE REMAINING

# ABE - RestAPI

This is a C++ Rest API for Attribute Based Encryption using [zeutro's openabe library](https://github.com/zeutro/openabe).

## Installation

1) install [microsoft's C++ Rest SDK](https://github.com/microsoft/cpprestsdk)
2) git clone https://github.com/babbadeckl/ABE-RestAPI
3) cd ABE-RestAPi
4) mkdir build
5) cd build
6) cmake ..
7) make
8) ./restserver

Afterwards the restserver should be running on localhost (Port 12345) (host and port can be changed in main.cpp)

## How to use

#### 1) Key generation based on Attributes:

/gen_attribute_keys?attribute=*attribute*

If there is more than one attribute, the attributes can be concatenated with '|' e.g Nurse|Age=23

#### 2) Key generation based on Policy:

/gen_policy_keys?policy=*policy*

Policies can be constructed by concatenating attributes with "or" and "and"

#### 3) Encrypion:

/encrypt?key=*key*&plaintext=*plaintext*

#### 4) Decryption:

/decrypt?key=*key*&ciphertext=*ciphertext*

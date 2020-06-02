import requests

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_passed(message, passed):
    print(f"\t[+] Test: {message} {bcolors.OKGREEN + '[PASSED]' + bcolors.ENDC if passed else bcolors.FAIL + '[FAILED]' + bcolors.ENDC}")


# Tests for Key-Policy ABE
def test_kp_gen_attribute_key(URL):
    key_gen_attribute = "gen_attribute_keys?scheme=kp&attribute=Doctor and Floor>=2"
    r = requests.get(URL + key_gen_attribute)
    return r.json()["key"]

def test_kp_encrypt(URL, plaintext):
    encrypt = "encrypt?scheme=kp&key=Doctor|Floor=2&plaintext=" + plaintext
    r = requests.get(URL + encrypt)
    return r.json()["ciphertext"]

def test_kp_encrypt_wrong_attributes(URL, plaintext):
    encrypt = "encrypt?scheme=kp&key=Teacher|Floor=1&plaintext=" + plaintext
    r = requests.get(URL + encrypt)
    return r.json()["ciphertext"]

def test_kp_decrypt(URL, ciphertext, key_attr):
    decrypt = "decrypt?scheme=kp&key=" + key_attr + "&ciphertext=" + ciphertext
    r = requests.get(URL + decrypt)
    return r.json()["plaintext"]




# Tests for Ciphertext-Policy ABE
def test_cp_gen_attribute_key(URL):
    key_gen_attribute = "gen_attribute_keys?scheme=cp&attribute=Doctor|Floor=2"
    r = requests.get(URL + key_gen_attribute)
    return r.json()["key"]

def test_cp_encrypt(URL, plaintext):
    encrypt = "encrypt?scheme=cp&key=Doctor and Floor<=4&plaintext=" + plaintext
    r = requests.get(URL + encrypt)
    return r.json()["ciphertext"]

def test_cp_encrypt_wrong_attributes(URL, plaintext):
    encrypt = "encrypt?scheme=cp&key=Doctor and Floor==4&plaintext=" + plaintext
    r = requests.get(URL + encrypt)
    return r.json()["ciphertext"]

def test_cp_decrypt(URL, ciphertext, key_attr):
    decrypt = "decrypt?scheme=cp&key=" + key_attr + "&ciphertext=" + ciphertext
    r = requests.get(URL + decrypt)
    return r.json()["plaintext"]



def test_kp_abe(URL):
    key_attr = test_kp_gen_attribute_key(URL)
    print_passed("Key generation", key_attr)

    plaintext = "Hello World!"
    ciphertext = test_kp_encrypt(URL, plaintext)
    print_passed("Encryption", ciphertext)
    ciphertext_2 = test_kp_encrypt_wrong_attributes(URL, plaintext);

    decrypted_ciphertext = test_kp_decrypt(URL, ciphertext, key_attr)
    print_passed("Successful Decryption", decrypted_ciphertext == plaintext)

    decrypted_ciphertext2 = test_kp_decrypt(URL, ciphertext_2, key_attr)
    print_passed("Decryption with wrong attributes should fail", decrypted_ciphertext2 != plaintext)




def test_cp_abe(URL):
    key_attr = test_cp_gen_attribute_key(URL)
    print_passed("Key generation", key_attr)
    plaintext = "Hello World!"
    
    ciphertext = test_cp_encrypt(URL, plaintext)
    print_passed("Encryption", ciphertext)
    ciphertext_2 = test_cp_encrypt_wrong_attributes(URL, plaintext)
    
    decrypted_ciphertext = test_cp_decrypt(URL, ciphertext, key_attr)
    print_passed("Successful Decryption", decrypted_ciphertext == plaintext)

    decrypted_ciphertext2 = test_cp_decrypt(URL, ciphertext_2, key_attr)
    print_passed("Decryption with wrong attributes should fail", decrypted_ciphertext2 != plaintext)






if __name__ == "__main__":
    URL = "http://127.0.0.1:12345/"
    print("### Testing Key-Policy ABE (KP-ABE)")
    test_kp_abe(URL);
    print("\n### Testing Ciphertext-Policy ABE (CP-ABE)")
    test_cp_abe(URL);






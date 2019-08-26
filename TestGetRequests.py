import requests

URL = "http://127.0.0.1:12345/"
keygen_attribute = "gen_attribute_keys?attribute=Doctor and (Floor > 2) and (Floor < 5) and Age>=15"
r = requests.get(URL + keygen_attribute)
key_attr = r.json()["key"]
print("######## ATTR KEY: " + key_attr + "\n")
plaintext = "Hello World!"

# keygen_policy = "gen_policy_keys?policy=test"
# r = requests.get(URL + keygen_policy)
# key_policy = r.json()["key"]
# print("######## POLICY KEY: " + key_policy)

encrypt = "encrypt?key=Doctor|Floor=4|Age=15&plaintext=" + plaintext
r = requests.get(URL + encrypt)
ciphertext = r.json()["ciphertext"]
print("######## CIPHERTEXT: " + ciphertext + "\n")

decrypt = "decrypt?key=" + key_attr + "&ciphertext=" + ciphertext
r = requests.get(URL + decrypt)
plaintext = r.json()
dict_key = list(plaintext.keys())[0]
print("####### PLAINTEXT: " + plaintext[dict_key]+ "\n")

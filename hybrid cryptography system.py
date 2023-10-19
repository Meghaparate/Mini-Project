import random
import time
blocksize=8
def pkcs5_padding(plaintext, block_size):
    if len(plaintext) % block_size != 0:
        padding_length = block_size - (len(plaintext) % block_size)
        padbit=chr(ord('A')+padding_length-1)
        padbit=bytes(padbit,'utf-8')
        plaintext += padbit * padding_length
    else:
        padbit='H'
        padbit=bytes(padbit,'utf-8')
        plaintext += padbit * blocksize
    return plaintext

def repeat_string(string, size):    #Repeat the secret key until it matches the length of the plaintext message.
        repetitions = size // len(string)
        remainder = size % len(string)
        repeated_string = string * repetitions + string[:remainder]
        return repeated_string
    
def divide_string(string, size):    #dividing plaintext in defined number of divisions
    substrings = [string[i:i+size] for i in range(0, len(string), size)]
    return substrings

def generate_random_numbers(n, start, end): #Generating random keys
    random_numbers = []
    for _ in range(n):
        random_numbers.append(random.randint(start, end)) 
    return random_numbers

def round_key_generator(string, start, size):    #Extracting keys for respective plaintexts
    accessed_string = ""
    length = len(string)
    start %= length
    end = (start + size) % length
    if start <= end:
        accessed_string = string[start:end]
    else:
        accessed_string = string[start:] + string[:end]
    return accessed_string

#ENCRYPTION
def vigenere_encrypt(plaintext, key):   #Encrypting plaintext using vigenere cipher
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if not char.isalpha():  # Ignore non-alphabetic characters
            ciphertext += char
            continue
        char_num = ord(char) - ord("A")  # Convert letter to a number (A=0, B=1, ...)
        key_num = ord(key[key_index % len(key)]) - ord("A")  # Get corresponding key number
        encrypted_num = (char_num + key_num) % 26  # Perform Vigenère encryption
        encrypted_char = chr(encrypted_num + ord("A"))  # Convert number back to letter
        ciphertext += encrypted_char
        key_index += 1
    return ciphertext

def polybius_encrypt(plain_text):    #Encrypting obtained vigenere ciphertext using polybius cipher
    polybius_grid = {
        'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15', 'F': '16', 'G': '17', 'H': '18',
        'I': '21', 'J': '22', 'K': '23', 'L': '24', 'M': '25', 'N': '26', 'O': '27', 'P': '28',
        'Q': '31', 'R': '32', 'S': '33', 'T': '34', 'U': '35', 'V': '36', 'W': '37', 'X': '38',
        'Y': '41', 'Z': '42', ' ': '43', '0': '44', '1': '45', '2': '46', '3': '47', '4': '48',
        '5': '51', '6': '52', '7': '53', '8': '54', '9': '55', '!': '56', '"': '57', '#': '58',
        '$': '61', '%': '62', '&': '63', "'":'64', '(': '65', ')': '66', '*': '67', '+': '68',
        ',': '71', '-': '72', '.': '73', '/': '74', ':': '75', ';': '76', '<': '77', '=': '78',
        '>': '81', '?': '82', '@': '83', '[': '84', '\\': '85', ']': '86', '^': '87', '\n': '88'
    }

    encrypted_text = ''
    for char in plain_text:
        if char in polybius_grid:
            encrypted_text += polybius_grid[char]
    return encrypted_text

def xor_operation(Ciphertext):
    polykey=random.randint(pow(10,len(Ciphertext)-1),pow(10,len(Ciphertext))-1)
    Ciphertext=int(Ciphertext)^polykey
    return Ciphertext, polykey

def polybius_decrypt(encrypted_text):
    polybius_grid = {
    '11': 'A', '12': 'B', '13': 'C', '14': 'D', '15': 'E', '16': 'F', '17': 'G', '18': 'H',
    '21': 'I', '22': 'J', '23': 'K', '24': 'L', '25': 'M', '26': 'N', '27': 'O', '28': 'P', 
    '31': 'Q', '32': 'R', '33': 'S', '34': 'T', '35': 'U', '36': 'V', '37': 'W', '38': 'X', 
    '41': 'Y', '42': 'Z', '43': ' ', '44': '0', '45': '1', '46': '2', '47': '3', '48': '4',
    '51': '5', '52': '6', '53': '7', '54': '8', '55': '9', '56': '!', '57': '"', '58': '#',
    '61': '$', '62': '%', '63': '&', '64': "'", '65': '(', '66': ')', '67': '*', '68': '+',
    '71': ',', '72': '-', '73': '.', '74': '/', '75': ':', '76': ';', '77': '<', '78': '=',
    '81': '>', '82': '?', '83': '@', '84': '[', '85': '\\', '86': ']', '87': '^', '88': '\n'
    }

    decrypted_text = ''
    digits = []
    for char in encrypted_text:
        digits.append(char)
        if len(digits) == 2:
            pair = ''.join(digits)
            if pair in polybius_grid:
                decrypted_text += polybius_grid[pair]
            digits = []
    return decrypted_text

def vigenere_decrypt(ciphertext, key):  #decrypting the ciphertext using vigenere cipher 
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""
    key_index = 0

    for char in ciphertext:
        if not char.isalpha():  # Ignore non-alphabetic characters
            plaintext += char
            continue
        char_num = ord(char) - ord("A")  # Convert letter to a number (A=0, B=1, ...)
        key_num = ord(key[key_index % len(key)]) - ord("A")  # Get corresponding key number
        decrypted_num = (char_num - key_num) % 26  # Perform Vigenère decryption
        decrypted_char = chr(decrypted_num + ord("A"))  # Convert number back to letter
        plaintext += decrypted_char
        key_index += 1

    return plaintext
def unpad(text):
    plaintext=""
    lastbit=text[-1]
    unpadding_length=ord(lastbit)-ord('A')+1
    plaintext = text[:-unpadding_length]
    return plaintext

##-----ENCRYPTION-----##
plaintext=b''
file = open('C:/Users/Megha Parate/OneDrive/Desktop/project/plaintext.txt', 'r')
while 1:
     
    # read by character
    char = file.read(1)         
    if not char:
        break  
    plaintext+=char.encode('utf-8')         #Taking data from the file
file.close()

key=input("Enter key:")
key=bytes(key,'utf-8')
start=time.time()
plaintext_blocksize = 8      #block size is 64bits
plaintext = plaintext.upper()       #Converting plaintext to uppercase
padded_plaintext_64_bits = pkcs5_padding(plaintext, plaintext_blocksize)
key = key.upper()       #Converting secret key to uppercase
key=repeat_string(key,len(padded_plaintext_64_bits))    #Repeat key until it become the size of plaintext
ExtractedKey=[]
vig_ciphertext=""
PlaintextBlocks = divide_string(padded_plaintext_64_bits, plaintext_blocksize)
number_of_blocks=len(PlaintextBlocks)

random_numbers = generate_random_numbers(number_of_blocks, 0, len(padded_plaintext_64_bits))

#Extract keys for respective ciphertext
for i in range(len(random_numbers)):
    div_str = round_key_generator(key, random_numbers[i], len(PlaintextBlocks[i]))
    ExtractedKey.append(div_str)

#Encrypt using vigenere cipher
for i in range(len(random_numbers)):
    cipherstr=vigenere_encrypt(PlaintextBlocks[i].decode(),ExtractedKey[i].decode())
    vig_ciphertext+=cipherstr
print()
print("Vigenere encrypted:",vig_ciphertext)
print()
#Encrypt using polybius cipher
polybius_ciphertext=polybius_encrypt(vig_ciphertext)
print("Polybius Encrypted text:",polybius_ciphertext)

Ciphertext,polykey= xor_operation(polybius_ciphertext)
print()
print("Final Ciphertext is in ciphertext.txt")
file = open('C:/Users/Megha Parate/OneDrive/Desktop/project/ciphertext.txt', 'w')
file.write(str(Ciphertext))
file.close()
end=time.time()
print()
print("TOTAL ENCRYPTION TIME:",end-start)

##-----DECRYPTION-----##
received_ciphertext=''     #recieved ciphertext
file = open('C:/Users/Megha Parate/OneDrive/Desktop/project/ciphertext.txt', 'r')
while 1:
     
    # read by character
    char = file.read(1)         
    if not char:
        break  
    received_ciphertext+=char         #Taking data from the file
file.close()
received_round_keys=random_numbers      #received round keys from sender
received_key=key        #received original key from sender
received_polykey=polykey
start=time.time()
div_received_key=[]
blocksize=8
plaintextstr=""
org_plaintext=""
polydecrypt=""

received_ciphertext=int(received_ciphertext)^polykey
received_ciphertext=str(received_ciphertext)
polydecrypted=polybius_decrypt(received_ciphertext)
print()
print("Polybius Decrypted: ",polydecrypted)

div_polyplaintext=divide_string(polydecrypted,blocksize)

#Extract keys for respective ciphertext
for i in range(len(received_round_keys)):
    div_str = round_key_generator(received_key, received_round_keys[i], len(div_polyplaintext[i]))
    div_received_key.append(div_str.decode())

#Decrypting using vigenere cipher
for i in range(len(received_round_keys)):
    plaintextstr = vigenere_decrypt(div_polyplaintext[i], div_received_key[i])
    org_plaintext += plaintextstr
print()
print("Vigenere Decrypted:",org_plaintext)
extracted_plaintext=unpad(org_plaintext)
print()
print("Message Received:",extracted_plaintext)
end=time.time()
print()
print("TOTAL DECRYPTION TIME:",end-start)

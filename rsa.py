import math, random, argparse, time
from Crypto.Util import number

print("""\u001b[33m
██████╗ ███████╗ █████╗ 
██╔══██╗██╔════╝██╔══██╗
██████╔╝███████╗███████║
██╔══██╗╚════██║██╔══██║
██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
Douglas Lopes  082170005
Luis Henrique  082170014
Igor Lacivita  082170035
Sabrina Bastos 082170027\u001b[0m
""")

parser = argparse.ArgumentParser(add_help=True, description="Programa de criptografia RSA")

def gen_keypar(p, q):
    n = p * q # Calcula N
    phi = (p-1) * (q-1) # Calcula Totient
    e = random.randrange(1, phi) # Calcula E
    g = math.gcd(e, phi)
    while g != 1:
       e = random.randrange(1, phi)
       g = math.gcd(e, phi)
    d = pow(e, -1, phi) # Calcula D
    return((e,n),(d,n))

def encrypt(pk, plaintext):
    unique_chars = ''.join(set(plaintext))
    encrypt_unique_chars = {}
  
    for char in unique_chars:
        char_code = ord(char)
        encrypted_char = pow(char_code, pk[0], pk[1])
        encrypt_unique_chars[char] = encrypted_char

    encrypt_text = []
    for char in plaintext:
        encrypt_text.append(encrypt_unique_chars.get(char))

    return encrypt_text

def decrypt(pk, ciphertext):
    unique_chars = list(set(ciphertext))
    decrypt_unique_chars = {}

    for char in unique_chars:
        decrypted_char = pow(char, pk[0], pk[1])
        char_value = chr(decrypted_char)
        decrypt_unique_chars[char] = char_value

    decrypt_text = ''
    for char in ciphertext:
        decrypt_text += decrypt_unique_chars.get(char)
        
    return decrypt_text

def time_convert(sec):
  mins = sec // 60
  sec = sec % 60
  hours = mins // 60
  mins = mins % 60
  print("Time Lapsed = {0}:{1}:{2}".format(int(hours),int(mins),sec))

def main():
    start_time = time.time()
    print("Gerando chaves...")   
    public, private = gen_keypar(number.getPrime(4096), number.getPrime(4096))
    print(f"Chave publica: \u001b[32m{public}\u001b[0m | Chave privada: \u001b[31m{private}\u001b[0m")

    print("Encriptando a mensagem...")
    encrypted_msg = encrypt(private,"The information security is of significant importance to ensure the privacy of communications")
    string_ints = [str(int) for int in encrypted_msg]
    print(f"A mensagem encriptada é: \u001b[36m{''.join(string_ints)}\u001b[0m")

    print("Descriptando a mensagem...")
    decrypted = decrypt(public, encrypted_msg)
    print(f"A mensagem descriptada é: \u001b[38;5;202m{decrypted}\u001b[0m")
    
    end_time = time.time()
    time_lapsed = end_time - start_time
    time_convert(time_lapsed)

if __name__ == '__main__':
    main()
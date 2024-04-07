from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

# função para gerar a chave AES
def gerar_chave_aes():
    # chave aes de 256 bits (32 bytes)
    return os.urandom(32)

# função para criptografar uma mensagem usando aes
def criptografar_mensagem(chave, mensagem):
    # padding
    padder = padding.PKCS7(128).padder()
    padded_dados = padder.update(mensagem.encode()) + padder.finalize()

    # inicializa o algoritimo aes em cbc
    # vetor de inicialização de 128 bits (16 bytes)
    iv = os.urandom(16)
    cifra = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    encriptador = cifra.encryptor()

    # criptografar a mensagem
    texto_cifra = encriptador.update(padded_dados) + encriptador.finalize()

    return iv + texto_cifra

# funcção para descriptografar uma mensagem
def descriptografar_mensagem(chave, mensagem_encriptografada):
    # separa o vetor de inicialização e o texto cifrado
    iv = mensagem_encriptografada[:16]
    texto_cifra = mensagem_encriptografada[16:]

    # inicializa o algoritimo aes em cbc
    cifra = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    descriptador = cifra.decryptor()

    # descriptografando a mensagem
    padded_dados = descriptador.update(texto_cifra) + descriptador.finalize()

    # remove o padding
    unpadder = padding.PKCS7(128).unpadder()
    mensagem = unpadder.update(padded_dados) + unpadder.finalize()

    return mensagem.decode()

# usando o aes
mensagem = "Hello, World!"
chave = gerar_chave_aes()
criptografar = criptografar_mensagem(chave, mensagem)
descriptografar = descriptografar_mensagem(chave, criptografar)

print("Mensagem original:", mensagem)
print("Mensagem criptografada:", criptografar)
print("Mensagem descriptografada:", descriptografar)

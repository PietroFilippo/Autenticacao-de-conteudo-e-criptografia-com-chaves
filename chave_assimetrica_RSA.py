from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# função para gerar um par de chaves rsa
def gerar_par_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

# funcção para criptografar uma mensagem
def encriptografar_mensagem(chave_publica, mensagem):
    # criptografar mensagem
    texto_cifra = chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return texto_cifra

# função para descriptografar a mensagem
def descriptografar_mensagem(chave_privada, texto_cifra):
    # descriptografar mensagem
    padded_dados = chave_privada.decrypt(
        texto_cifra,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return padded_dados.decode()

# uso do rsa
mensagem = "Hello, World!"
chave_privada, chave_publica = gerar_par_chaves()
encriptografar = encriptografar_mensagem(chave_publica, mensagem)
descriptografar = descriptografar_mensagem(chave_privada, encriptografar)

print("Mensagem original:", mensagem)
print("Mensagem criptografada:", encriptografar)
print("Mensagem descriptografada:", descriptografar)
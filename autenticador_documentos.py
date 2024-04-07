import sys
import hashlib
import os
from shutil import copyfile
from PyPDF2 import PdfReader
from docx import Document
from datetime import datetime

# calcula hash sha-256 do documento e retornando em hexadecimal
def calcular_hash(file_path):
    with open(file_path, 'rb') as file:
        hash_sha256 = hashlib.sha256()
        for chunk in iter(lambda: file.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

# autentica o documento
def autenticar_documento(doc_path):
    # cria um arquivo temporário com a extensão do arquivo original
    temp_path = f'temp{os.path.splitext(doc_path)[1]}'
    copyfile(doc_path, temp_path)
    try:
        if doc_path.endswith('.pdf'):
            # arquivos PDF
            with open(temp_path, 'rb') as file:
                pdf_reader = PdfReader(file)
                if pdf_reader.is_encrypted:
                    return False, f"O PDF '{doc_path}' possui criptografia e não pode ser autenticado"
                else:
                    hash_conteudo = calcular_hash(temp_path)
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    return True, f"Hash do PDF '{doc_path}': {hash_conteudo}", hash_conteudo, now
        elif doc_path.endswith('.docx'):
            # arquivos DOCX
            docx_doc = Document(temp_path)
            hash_conteudo = hashlib.sha256()
            for paragraph in docx_doc.paragraphs:
                hash_conteudo.update(paragraph.text.encode('utf-8'))
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return True, f"Hash do DOCX '{doc_path}': {hash_conteudo.hexdigest()}", hash_conteudo.hexdigest(), now
        elif doc_path.endswith(('.jpg', '.jpeg')):
            # arquivos JPEG
            hash_conteudo = calcular_hash(temp_path)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return True, f"Hash do JPEG '{doc_path}': {hash_conteudo}", hash_conteudo, now
        else:
            return False, "Formato de arquivo não é suportado", None, None
    finally:
        # remove o arquivo temporário após a execução
        os.remove(temp_path)

# verifica a autenticação do documento
def verificar_autenticacao(doc_path, hash_atual):
    if os.path.exists('hashes.txt'):
        with open('hashes.txt', 'r') as hash_file:
            for line in hash_file:
                if doc_path in line:
                    hash_anterior = line.split(",")[1].split(": ")[1].strip()
                    return hash_anterior == hash_atual
    return True

# função principal
def main():
    if len(sys.argv) != 2:
        print("Para usar insira: python autenticador.py <arquivo> ou <caminho/para/arquivo> ")
    else:
        arquivo = sys.argv[1]
        if os.path.exists(arquivo):
            sucesso, mensagem, hash_atual, now = autenticar_documento(arquivo)
            if sucesso:
                autenticado_previa = verificar_autenticacao(arquivo, hash_atual)
                if autenticado_previa:
                    print("O arquivo não foi modificado desde a última autenticação")
                else:
                    print("O arquivo foi modificado desde a última autenticação")
                with open('hashes.txt', 'a') as hash_file:
                    modificacao = "original" if autenticado_previa else "modificado"
                    hash_file.write(f"Nome original do documento ({modificacao}): {arquivo}, Hash {modificacao}: {hash_atual}, Data/Hora: {now}\n")
            else:
                print("Falha na autenticação", mensagem)
        else:
            print("O arquivo não existe")

if __name__ == "__main__":
    main()

import base64
from Crypto.Cipher import AES
from .security_exception import SecurityException


class Encrypter:

    def __init__(self, key, salt=None):
        """
        Inicia o objeto com chave e salt
        :param key: Chave de criptografia
        :type key: str
        :param salt: Salt criptográfico
        :type salt: str
        """
        self.key = key.encode('utf-8')
        self.salt = salt.encode('utf-8')

    def encrypt(self, plaintext) -> str:
        """
        Criptografa uma string
        :param plaintext: Texto a ser criptografado
        :type plaintext: str
        :return: Cifra do texto
        :rtype: str
        """
        if plaintext == "":
            raise SecurityException("Text to be encyrpted is empty")
        try:
            aes = AES.new(self.key, AES.MODE_EAX, self.salt)
            enc = aes.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(enc).decode("utf-8")
        except Exception as e:
            raise SecurityException(f"Could not encrypt. {str(e)}")

    def decrypt(self, encrypted) -> str:
        """
        Descriptografa uma cifra
        :param encrypted: Cifra
        :type encrypted: str
        :return: Texto descriptografado
        :rtype: str
        """
        if encrypted == "":
            raise SecurityException("Text to be decrypted is empty")
        try:
            enc = base64.b64decode(encrypted.encode("utf-8"))
            aes = AES.new(self.key, AES.MODE_EAX, self.salt)
            return aes.decrypt(enc).decode("utf-8")
        except Exception as e:
            raise SecurityException(f"Could not decrypt. {str(e)}")

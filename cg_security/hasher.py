import hashlib
from .security_exception import SecurityException


def blake2b(plaintext) -> str:
    """
    Cria o hash Blake2b da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.blake2b(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))


def blake2s(plaintext):
    """
    Cria o hash Blake2s da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.blake2s(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))


def md5_hash(plaintext):
    """
    Cria o hash MD5 da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.md5(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))


def sha1_hash(plaintext):
    """
    Cria o hash SHA1 da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.sha1(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))


def sha256_hash(plaintext):
    """
    Cria o hash SHA256 da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.sha256(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))


def sha512_hash(plaintext):
    """
    Cria o hash SHA512 da string
    :param plaintext: String a ser feito o hash
    :type plaintext: str
    :return: Hash
    :rtype: str
    """
    try:
        return hashlib.sha512(plaintext.encode()).hexdigest()
    except Exception as e:
        raise SecurityException(str(e))
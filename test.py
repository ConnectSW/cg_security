from cg_security.encrypter import Encrypter

key = '0123456789012345'
salt = '5432109876543210'

e = Encrypter(key, salt)
cypher = e.encrypt('bozoloco')
print(cypher)
text = e.decrypt(cypher)
print(text)
# coding: utf-8
# pip install flask flask-jsonpify flask-sqlalchemy flask-restful flask-cors pycryptodome
from flask import request, Flask
from flask_cors import CORS
from flask_restful import Resource, Api

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64decode

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
api = Api(app)

# Generate RSA key pair (public and private)
key_pair = RSA.generate(1024)
private_key = open("private_key.pem", "wb")  # fix: write as binary
private_key.write(key_pair.exportKey())
private_key.close()
public_key = open("public_key.pem", "wb")  # fix: write as binary
public_key.write(key_pair.publickey().exportKey())
public_key.close()

# fix: read file as binary
def file_get_contents(filename):
    with open(filename, "rb") as f:
        return f.read()

class Main(Resource):
    def get(self):
        return file_get_contents("public_key.pem").decode()  # return string for browser display

    def post(self):
        message = request.form.get('message')
        key = RSA.importKey(file_get_contents("private_key.pem"))
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        decrypted_message = cipher.decrypt(b64decode(message))
        print(decrypted_message)
        return decrypted_message.decode()  # return string for response

api.add_resource(Main, '/')

if __name__ == '__main__':
    app.run(port=5000)

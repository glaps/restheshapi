import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.route("/api")
def api():
    return jsonify({'encryptdata':['pass','text'],'decryptdata':['pass','hash']})

@app.route('/api/encryptdata', methods=['POST'])
def encrypt():
    return jsonify({"you_data": AESq(request.json['pass'].encode('utf-8')).encrypt(request.json['text']).decode("utf-8"),"you_pass":request.json['pass']})

@app.route('/api/decryptdata', methods=['POST'])
def decrypt():
    return jsonify({"you_data": AESq(request.json['pass'].encode('utf-8')).decrypt(request.json['hash'])})




class AESq():
    def __init__(self, key):
        self.bss = 32
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, r):
        r = self._pad(r)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(r))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, st):
        return st + (self.bss - len(st) % self.bss) * chr(self.bss - len(st) % self.bss)

    @staticmethod
    def _unpad(st):
        return st[:-ord(st[len(st)-1:])]

if __name__ == '__main__':
    app.run(debug=True)


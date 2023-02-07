from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import os




app = Flask(__name__, static_folder='static', template_folder='templates')
auth = HTTPBasicAuth()

user = os.environ.get('USER')
password = os.environ.get('PASSWORD')
flag = os.environ.get('FLAG')

users = {
    user : generate_password_hash(secretpassw0rd),
}


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12345)
    
    def digest(self):
        """Compute the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        :Return: the MAC, as a byte string.
        """

        if "digest" not in self._next:
            raise TypeError("digest() cannot be called when decrypting"
                                " or validating a message")
        self._next = ["digest"]

        if not self._mac_tag:
            tag = b'\x00' * self.block_size
            for i in range(3):
                tag = strxor(tag, self._omac[i].digest())
            self._mac_tag = tag[:self._mac_len]

        return self._mac_tag

    def hexdigest(self):
        """Compute the *printable* MAC tag.

        This method is like `digest`.

        :Return: the MAC, as a hexadecimal string.
        """
        return "".join(["%02x" % bord(x) for x in self.digest()])

    def verify(self, received_mac_tag):
        """Validate the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method checks if the decrypted message is indeed valid
        (that is, if the key is correct) and it has not been
        tampered with while in transit.

        :Parameters:
          received_mac_tag : bytes/bytearray/memoryview
            This is the *binary* MAC, as received from the sender.
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if "verify" not in self._next:
            raise TypeError("verify() cannot be called"
                                " when encrypting a message")
        self._next = ["verify"]

        if not self._mac_tag:
            tag = b'\x00' * self.block_size
            for i in range(3):
                tag = strxor(tag, self._omac[i].digest())
            self._mac_tag = tag[:self._mac_len]

        secret = get_random_bytes(16)

        mac1 = BLAKE2s.new(digest_bits=160, key=secret, data=self._mac_tag)
        mac2 = BLAKE2s.new(digest_bits=160, key=secret, data=received_mac_tag)

        if mac1.digest() != mac2.digest():
            raise ValueError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Validate the *printable* MAC tag.

        This method is like `verify`.

        :Parameters:
          hex_mac_tag : string
            This is the *printable* MAC, as received from the sender.
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    def encrypt_and_digest(self, plaintext, output=None):
        """Perform encrypt() and digest() in one step.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The piece of data to encrypt.
        :Keywords:
          output : bytearray/memoryview
            The location where the ciphertext must be written to.
            If ``None``, the ciphertext is returned.
        :Return:
            a tuple with two items:

            - the ciphertext, as ``bytes``
            - the MAC tag, as ``bytes``

            The first item becomes ``None`` when the ``output`` parameter
            specified a location for the result.
        """

        return self.encrypt(plaintext, output=output), self.digest()

    def decrypt_and_verify(self, ciphertext, received_mac_tag, output=None):
        """Perform decrypt() and verify() in one step.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The piece of data to decrypt.
          received_mac_tag : bytes/bytearray/memoryview
            This is the *binary* MAC, as received from the sender.
        :Keywords:
          output : bytearray/memoryview
            The location where the plaintext must be written to.
            If ``None``, the plaintext is returned.
        :Return: the plaintext as ``bytes`` or ``None`` when the ``output``
            parameter specified a location for the result.
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        pt = self.decrypt(ciphertext, output=output)
        self.verify(received_mac_tag)
        return pt


def _create_eax_cipher(factory, **kwargs):
    """Create a new block cipher, configured in EAX mode.

    :Parameters:
      factory : module
        A symmetric cipher module from `Crypto.Cipher` (like
        `Crypto.Cipher.AES`).

    :Keywords:
      key : bytes/bytearray/memoryview
        The secret key to use in the symmetric cipher.

      nonce : bytes/bytearray/memoryview
        A value that must never be reused for any other encryption.
        There are no restrictions on its length, but it is recommended to use
        at least 16 bytes.

        The nonce shall never repeat for two different messages encrypted with
        the same key, but it does not need to be random.

        If not specified, a 16 byte long random string is used.

      mac_len : integer
        Length of the MAC, in bytes. It must be no larger than the cipher
        block bytes (which is the default).
    """

    try:
        key = kwargs.pop("key")
        nonce = kwargs.pop("nonce", None)
        if nonce is None:
            nonce = get_random_bytes(16)
        mac_len = kwargs.pop("mac_len", factory.block_size)
    except KeyError as e:
        raise TypeError("Missing parameter: " + str(e))

    return EaxMode(factory, key, nonce, mac_len, kwargs)




from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import os




app = Flask(__name__, static_folder='static', template_folder='templates')
auth = HTTPBasicAuth()


user = os.environ.get('USER')
password = os.environ.get('PASSWORD')
users = {
    user : generate_password_hash(password),
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12345)

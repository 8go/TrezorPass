from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

try:
	import cPickle as pickle
except Exception:
	import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random

import encoding
from basics import Magic


class Backup(object):
	"""
	Performs backup and restore for password storage
	"""

	RSA_KEYSIZE = 4096  # in bits
	SYMMETRIC_KEYSIZE = 32
	BLOCKSIZE = 16
	RSA_BLOCKSIZE = RSA_KEYSIZE // 8  # in bytes
	SAFE_RSA_BLOCKSIZE_WITHOUTBUFFER = RSA_BLOCKSIZE - 2 - 2 * 32  # 446 # 4096 // 8 - 2 - 2*32

	def __init__(self, trezor):
		"""
		Create with no keys prepared.

		@param trezor: Trezor client object to use for encrypting private
			key
		"""
		self.encryptedPrivate = None  # encrypted private key
		self.encryptedEphemeral = None  # ephemeral key used to encrypt private RSA key
		self.ephemeralIv = None  # IV used to encrypt private key with ephemeral key
		self.publicKey = None
		self.trezor = trezor

	def generate(self):
		"""
		Generate key and encrypt private key
		"""
		key = RSA.generate(self.RSA_KEYSIZE)
		privateDer = key.exportKey(format="DER")
		self.publicKey = key.publickey()
		self.wrapPrivateKey(privateDer)

	def wrapPrivateKey(self, privateKey):
		"""
		Wrap serialized private key by encrypting it with trezor.
		"""
		"""
		Trezor client won't allow to encrypt whole serialized RSA key
		in one go - it's too big. We need an ephemeral symmetric key
		and encrypt the small ephemeral with Trezor.
		"""
		rng = Random.new()
		ephemeral = rng.read(self.SYMMETRIC_KEYSIZE)
		self.ephemeralIv = rng.read(self.BLOCKSIZE)
		cipher = AES.new(ephemeral, AES.MODE_CBC, self.ephemeralIv)
		padded = encoding.Padding(self.BLOCKSIZE).pad(privateKey)
		self.encryptedPrivate = cipher.encrypt(padded)

		self.encryptedEphemeral = self.trezor.encrypt_keyvalue(
			Magic.backupNode, Magic.backupKey, ephemeral,
			ask_on_encrypt=False, ask_on_decrypt=True)

	def unwrapPrivateKey(self):
		"""
		Decrypt private RSA key using self.encryptedEphemeral from
		self.encryptedPrivate.

		Encrypted ephemeral key will be decrypted with Trezor.

		@returns RSA private key as Crypto.RSA._RSAobj
		"""
		ephemeral = self.trezor.decrypt_keyvalue(Magic.backupNode,
			Magic.backupKey, self.encryptedEphemeral,
			ask_on_encrypt=False, ask_on_decrypt=True)

		cipher = AES.new(ephemeral, AES.MODE_CBC, self.ephemeralIv)
		padded = cipher.decrypt(self.encryptedPrivate)
		privateDer = encoding.Padding(self.BLOCKSIZE).unpad(padded)

		privateKey = RSA.importKey(privateDer)
		return privateKey

	def serialize(self):
		"""
		Return object data as serialized string.
		"""
		publicDer = self.publicKey.exportKey(format="DER")
		picklable = (self.ephemeralIv, self.encryptedEphemeral,
			self.encryptedPrivate, publicDer)
		return pickle.dumps(picklable, pickle.HIGHEST_PROTOCOL)

	def deserialize(self, serialized):
		"""
		Set object data from serialized string
		"""
		# Py2-vs-Py3: loads in Py2 does only have 1 arg, all 4 args are required for Py3
		try:  # Py2-vs-Py3:
			unpickled = pickle.loads(serialized, fix_imports=True, encoding='bytes', errors='strict')
		except Exception:
			unpickled = pickle.loads(serialized)
		(self.ephemeralIv, self.encryptedEphemeral,
			self.encryptedPrivate, publicDer) = unpickled
		self.publicKey = RSA.importKey(publicDer)

	def encryptPassword(self, password):
		"""
		Encrypt password with RSA under OAEP padding and return it.
		Password must be shorter than modulus length minus padding
		length.

		With a 4096 bit RSA key that results in a maximum length of
		470 bytes for the plaintext for this implementation (4096//8-2*hashsize-2).

		@param password: password entry, key/value pair
		@type pasword: string (unicode)
		@returns: encrypted passwords of type bytes
		"""
		cipher = PKCS1_OAEP.new(self.publicKey)
		# With a 4096 bit RSA key PKCS1_OAEP.cipher.encrypt() has as limit a maximum
		# length of 470 bytes for the plaintext in this implementation
		# (4096//8-2*hashsize-2).
		# The resulting encrypted block is of size 512 bytes.
		# To allow larger plain text we junk the plaintext into 446 byte pieces
		# (so that it would work also in the future with larger hashsizes).
		# RSA-only is not ideal, but should be acceptable.
		# See https://security.stackexchange.com/questions/33434
		encrypted = b''
		passwordBytes = encoding.tobytes(password)
		splits = [passwordBytes[x:x+self.SAFE_RSA_BLOCKSIZE_WITHOUTBUFFER]
			for x in range(0, len(passwordBytes), self.SAFE_RSA_BLOCKSIZE_WITHOUTBUFFER)]
		for junk in splits:
			encrypted += cipher.encrypt(junk)
		# print "RSA PKCS encryption: plain-size =", len(passwordBytes), ", encrypted-size =", len(encrypted)
		return encrypted

	def decryptPassword(self, encryptedPassword, privateKey):
		"""
		Decrypt RSA-OAEP encrypted password.
		@param encryptedPassword: encrypted password entry, key/value pair
		@type encryptedPassword: bytes
		@returns: decrypted pasword of type string (unicode)
		"""
		cipher = PKCS1_OAEP.new(privateKey)
		passwordBytes = b''
		splits = [encryptedPassword[x:x+self.RSA_BLOCKSIZE]
			for x in range(0, len(encryptedPassword), self.RSA_BLOCKSIZE)]
		for junk in splits:
			passwordBytes += cipher.decrypt(junk)

		return(encoding.normalize_nfc(passwordBytes))

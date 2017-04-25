import cPickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random

from encoding import Magic, Padding

class Backup(object):
	"""
	Performs backup and restore for password storage
	"""
	
	RSA_KEYSIZE = 4096 # in bits
	SYMMETRIC_KEYSIZE = 32
	BLOCKSIZE = 16
	RSABLOCKSIZE = RSA_KEYSIZE / 8 # in bytes
	SAFERSABLOCKSIZEWITHOUTBUFFER = RSABLOCKSIZE - 2 - 2 * 32 # 446 # 4096 / 8 - 2 - 2*32

	
	def __init__(self, trezor):
		"""
		Create with no keys prepared.
		
		@param trezor: Trezor client object to use for encrypting private
			key
		"""
		self.encryptedPrivate = None #encrypted private key
		self.encryptedEphemeral = None #ephemeral key used to encrypt private RSA key
		self.ephemeralIv = None #IV used to encrypt private key with ephemeral key
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
		#Trezor client won't allow to encrypt whole serialized RSA key
		#in one go - it's too big. We need an ephemeral symmetric key
		#and encrypt the small ephemeral with Trezor.
		rng = Random.new()
		ephemeral = rng.read(self.SYMMETRIC_KEYSIZE)
		self.ephemeralIv = rng.read(self.BLOCKSIZE)
		cipher = AES.new(ephemeral, AES.MODE_CBC, self.ephemeralIv)
		padded = Padding(self.BLOCKSIZE).pad(privateKey)
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
		privateDer = Padding(self.BLOCKSIZE).unpad(padded)
		
		privateKey = RSA.importKey(privateDer)
		return privateKey
	
	def serialize(self):
		"""
		Return object data as serialized string.
		"""
		publicDer = self.publicKey.exportKey(format="DER")
		picklable = (self.ephemeralIv, self.encryptedEphemeral,
		     self.encryptedPrivate, publicDer)
		return cPickle.dumps(picklable, cPickle.HIGHEST_PROTOCOL)

	def deserialize(self, serialized):
		"""
		Set object data from serialized string
		"""
		unpickled = cPickle.loads(serialized)
		(self.ephemeralIv, self.encryptedEphemeral,
		     self.encryptedPrivate, publicDer) = unpickled
		self.publicKey = RSA.importKey(publicDer)
	
	def encryptPassword(self, password):
		"""
		Encrypt password with RSA under OAEP padding and return it.
		Password must be shorter than modulus length minus padding
		length.

		With a 4096 bit RSA key that results in a maximum length of
		470 bytes for the plaintext for this implementation (4096/8-2*hashsize-2).
		"""
		cipher = PKCS1_OAEP.new(self.publicKey)
		# With a 4096 bit RSA key PKCS1_OAEP.cipher.encrypt() has as limit a maximum
		# length of 470 bytes for the plaintext in this implementation 
		# (4096/8-2*hashsize-2).
		# The resulting encrypted block is of size 512 bytes.
		# To allow larger plain text we junk the plaintext into 446 byte pieces
		# (so that it would work also in the future with larger hashsizes). 
		# RSA-only is not ideal, but should be acceptable.
		# See https://security.stackexchange.com/questions/33434
		encrypted = ""
		splits=[password[x:x+self.SAFERSABLOCKSIZEWITHOUTBUFFER] for x in range(0,len(password),self.SAFERSABLOCKSIZEWITHOUTBUFFER)]
		for junk in splits:
			encrypted += cipher.encrypt(junk)
		# print "RSA PKCS encryption: plain-size =", len(password), ", encrypted-size =", len(encrypted)
		return encrypted
	
	def decryptPassword(self, encryptedPassword, privateKey):
		"""
		Decrypt RSA-OAEP encrypted password.
		"""
		cipher = PKCS1_OAEP.new(privateKey)
		password = ""
		splits=[encryptedPassword[x:x+self.RSABLOCKSIZE] for x in range(0,len(encryptedPassword),self.RSABLOCKSIZE)]
		for junk in splits:
			password += cipher.decrypt(junk)
		
		return password


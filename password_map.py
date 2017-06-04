from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import struct
import hmac
import hashlib
import logging
import traceback
import binascii
import copy
try:
	import cPickle as pickle
except Exception:
	import pickle

from Crypto.Cipher import AES
from Crypto import Random

from trezorlib.client import CallException, PinException

import basics
from encoding import normalize_nfc, tobytes, Padding
from backup import Backup
import processing

"""
On-disk format
.4 bytes...header b'TZPW'
.4 bytes...data storage version, network order uint32_t ==> see basics.PWDB_FILEFORMAT_VERSION
32 bytes...AES-CBC-encrypted wrappedOuterKey
16 bytes...IV
.2 bytes...backup private key size (B)
.B bytes...encrypted backup key
.4 bytes...size of data following (N)
.N bytes...AES-CBC encrypted blob containing pickled structure for password map
32 bytes...HMAC-SHA256 over data with same key as AES-CBC data struct above
"""

BLOCKSIZE = 16  # bytes
MACSIZE = 32
KEYSIZE = 32  # bytes


class PasswordGroup(object):
	"""
	Holds data for one password group.
	Each entry has three values:
	1 key
	2 symetrically AES-CBC encrypted password unlockable only by Trezor
	3 RSA-encrypted password for creating backup of all password groups
	"""

	def __init__(self):
		self.entries = []  # list of tuples

	def addEntry(self, key, encryptedValue, backupValue):
		"""Add key-value-backup entry"""
		self.entries.append((key, encryptedValue, backupValue))

	def removeEntry(self, idx):
		"""Remove entry at given index"""
		self.entries.pop(idx)

	def updateEntry(self, idx, key, encryptedValue, backupValue):
		"""
		Update pair at index idx with given key, value and
		backup-encrypted password.
		"""
		self.entries[idx] = (key, encryptedValue, backupValue)

	def entry(self, idx):
		"""Return entry with given index"""
		return self.entries[idx]

	def entrieslist(self):
		"""Return entries"""
		return(self.entries)

	def __str__(self):
		try:
			ss = u'[\n'
			for ee in self.entries:
				ss += u'(\t%s\n\t%s\n\t%s\n)' % (normalize_nfc(ee[0]),
					binascii.hexlify(ee[1]), binascii.hexlify(ee[2]))
			return(ss+u'\n]')
		except Exception:
			ss = u'[\n'
			mydict = self.__dict__
			for instvarkey in mydict:
				instvarval = mydict[instvarkey]
				for ee in instvarval:
					ss += u'(\t%s\n\t%s\n\t%s\n)' % (normalize_nfc(ee[0]),
						normalize_nfc(binascii.hexlify(ee[1])),
						normalize_nfc(binascii.hexlify(ee[2])))
			return(ss+u'\n]')


class PasswordMap(object):
	"""Storage of groups of passwords in memory"""

	MAX_PADDED_TREZOR_ENCRYPT_SIZE = 1024
	MAX_UNPADDED_TREZOR_ENCRYPT_SIZE = MAX_PADDED_TREZOR_ENCRYPT_SIZE - 1

	def __init__(self, trezor, settings):
		assert trezor is not None
		self.groups = {}  # dict with values being PasswordGroup instances
		self.trezor = trezor
		self.outerKey = None  # outer AES-CBC key
		self.outerIv = None  # IV for data blob encrypted with outerKey
		self.backupKey = None  # instance of class backup.Backup
		self.version = None
		self.settings = settings

		rng = Random.new()
		self.outerIv = rng.read(BLOCKSIZE)
		self.outerKey = rng.read(KEYSIZE)

	def addGroup(self, groupName):
		"""
		Add group by name as utf-8 encoded string
		"""
		if groupName in self.groups:
			raise KeyError("Password group already exists")

		self.groups[groupName] = PasswordGroup()

	def copyGroup(self, groupName):
		"""
		Creates a copy of a group by name as utf-8 encoded string
		"""
		if groupName not in self.groups:
			raise KeyError("Password group does not exist")
		return(copy.deepcopy(self.groups[groupName]))

	def renameGroup(self, groupNameOld, groupNameNew):
		"""
		Creates a copy of a group by name as utf-8 encoded string
		with a new group name.
		A more appropriate name for the method would be:
		createRenamedGroup().
		Since the entries inside the group are encrypted
		with the groupName, we cannot simply make a copy.
		We must decrypt with old name and afterwards encrypt
		with new name.
		If the group has many entries, each entry would require a 'Confirm'
		press on Trezor. So, to mkae it faster and more userfriendly
		we use the backup key to decrypt. This requires a single
		Trezor 'Confirm' press independent of how many entries there are
		in the group.
		@param groupNameOld: name of group to copy and rename
		@type groupNameOld: string
		@param groupNameNew: name of group to be created
		@type groupNameNew: string
		"""
		if groupNameOld not in self.groups:
			raise KeyError("Password group does not exist")
		groupNew = PasswordGroup()
		groupOld = self.groups[groupNameOld]

		try:
			privateKey = self.backupKey.unwrapPrivateKey()
		except CallException:
			return

		for entry in groupOld.entries:
			key, _, bkupPw = entry
			decryptedPwComments = self.backupKey.decryptPassword(bkupPw, privateKey)
			encPw = self.encryptPassword(decryptedPwComments, groupNameNew)
			groupNew.addEntry(key, encPw, bkupPw)

		return(groupNew)

	def replaceGroup(self, groupName, group):
		"""
		Replace group by name as utf-8 encoded string
		"""
		if groupName not in self.groups:
			raise KeyError("Password group does not exist")

		self.groups[groupName] = group

	def loadWithChecks(self, fname):
		"""
		Same as load() but with extra checks.

		@throws IOError: if reading file failed
		"""
		try:
			self.load(fname)
		except PinException:
			self.settings.mlooger.log("Invalid Trezor PIN entered. Aborting.",
				logging.CRITICAL, "Trezor IO")
			sys.exit(8)
		except CallException:
			# this is never reached, there is a sys.exit in the Cancel button
			self.settings.mlooger.log("User requested to quit (Esc, Cancel).",
				logging.CRITICAL, "Trezor IO")
			# button cancel on Trezor, so exit
			sys.exit(6)
		except IOError as e:
			self.settings.mlogger.log("IO Error: Could not decrypt password "
				"database file: %s" % (e), logging.CRITICAL, "Trezor IO")
			sys.exit(5)
		except Exception as e:
			self.settings.mlogger.log("Could not decrypt passwords: %s "
				"Aborting." % (e),
				logging.CRITICAL, "Trezor IO")
			traceback.print_exc()  # prints to stder
			sys.exit(5)

	def load(self, fname):
		"""
		Load encrypted passwords from disk file, decrypt outer
		layer containing key names. Requires Trezor connected.

		@throws IOError: if reading file failed
		"""
		self.settings.mlogger.log("Trying to load file '%s'." % (fname),
			logging.DEBUG, "File IO")
		with open(fname, "rb") as f:
			header = f.read(len(basics.Magic.headerStr))
			if header != basics.Magic.headerStr:
				raise IOError("Bad header in storage file")
			version = f.read(4)
			upkv = struct.unpack("!I", version)[0]
			if len(version) != 4 or (upkv != 1 and upkv != 2):
				raise IOError("Unknown version of storage file")
			self.version = upkv

			wrappedKey = f.read(KEYSIZE)
			if len(wrappedKey) != KEYSIZE:
				raise IOError("Corrupted disk format - bad wrapped key length")

			self.outerKey = self.unwrapKey(wrappedKey)

			self.outerIv = f.read(BLOCKSIZE)
			if len(self.outerIv) != BLOCKSIZE:
				raise IOError("Corrupted disk format - bad IV length")

			lb = f.read(2)
			if len(lb) != 2:
				raise IOError("Corrupted disk format - bad backup key length")
			lb = struct.unpack("!H", lb)[0]

			self.backupKey = Backup(self.trezor)
			serializedBackup = f.read(lb)
			if len(serializedBackup) != lb:
				raise IOError("Corrupted disk format - "
				"not enough encrypted backup key bytes")
			try:
				self.backupKey.deserialize(serializedBackup)
			except ValueError as e:
				raise ValueError("Critical error reading database [bk]: '%s'\n"
					"If error is `unsupported pickle protocol: 4` then you "
					"are trying to open with Python 2 a database file created "
					"with Python 3. Use Python 3 instead of Python 2. If you "
					"must use Python 2, then export the databse to CSV in "
					"Python 3 and import the CSV in Python 2." % (e))

			ls = f.read(4)
			if len(ls) != 4:
				raise IOError("Corrupted disk format - bad data length")
			ll = struct.unpack("!I", ls)[0]

			encrypted = f.read(ll)
			if len(encrypted) != ll:
				raise IOError("Corrupted disk format - not enough data bytes")

			hmacDigest = f.read(MACSIZE)
			if len(hmacDigest) != MACSIZE:
				raise IOError("Corrupted disk format - HMAC not complete")

			# time-invariant HMAC comparison that also works with python 2.6
			newHmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			hmacCompare = 0
			for (ch1, ch2) in zip(hmacDigest, newHmacDigest):
				hmacCompare |= int(ch1 != ch2)
			if hmacCompare != 0:
				raise IOError("Corrupted disk format - HMAC does not match "
					"or bad passphrase. Try with a different passphrase.")

			serialized = self.decryptOuter(encrypted, self.outerIv)

			# Py2-vs-Py3: loads in Py2 does only have 1 arg, all 4 args are required for Py3
			if sys.version_info[0] < 3:  # Py2-vs-Py3:
				try:
					self.groups = pickle.loads(serialized)
				except ValueError as e:
					raise ValueError("Critical error reading database [pw]: '%s'\n"
						"If error is `unsupported pickle protocol: 4` then you "
						"are trying to open with Python 2 a database file created "
						"with Python 3. Use Python 3 instead of Python 2. If you "
						"must use Python 2, then export the databse to CSV in "
						"Python 3 and import the CSV in Python 2." % (e))
				# # print example record for debugging
				# self.settings.mlogger.log("Group 0 as example: \n{%s : %s, ...}\n%s" %
				# 	(self.groups.keys()[0], self.groups[self.groups.keys()[0]],
				# 	vars(self.groups[self.groups.keys()[0]])),
				# 	logging.DEBUG, "Unpickled data")
			else:
				# loads is different in Py3
				tmpGroups = pickle.loads(serialized, fix_imports=True, encoding='bytes', errors='strict')
				# on the first time we open a pwdb file written in Py2 with Py3
				# we need to migrate the data to adjust to str vs bytes problem
				try:
					len(tmpGroups) > 0 and tmpGroups[list(tmpGroups.keys())[0]].entries
				except AttributeError:
					tmpGroups = processing.migrateUnpickledDataFromPy2ToPy3(tmpGroups, self.settings)
				self.groups = tmpGroups
				# # print example record for debugging
				# self.settings.mlogger.log("Group 0 as example: \n{%s : %s, ...}\n%s" %
				# 	(list(self.groups.keys())[0], self.groups[list(self.groups.keys())[0]],
				# 	vars(self.groups[list(self.groups.keys())[0]])),
				# 	logging.DEBUG, "Unpickled data")

			self.groups = processing.migrateToUnicode(self.groups, self.settings)

	def save(self, fname):
		"""
		Write password database to disk, encrypt it. Requires Trezor
		connected.

		@throws IOError: if writing file failed
		"""
		assert len(self.outerKey) == KEYSIZE
		rnd = Random.new()
		self.outerIv = rnd.read(BLOCKSIZE)
		wrappedKey = self.wrapKey(self.outerKey)

		with open(fname, "wb") as f:
			version = basics.PWDB_FILEFORMAT_VERSION
			f.write(basics.Magic.headerStr)
			f.write(struct.pack("!I", version))
			f.write(wrappedKey)
			f.write(self.outerIv)
			serialized = pickle.dumps(self.groups, pickle.HIGHEST_PROTOCOL)
			encrypted = self.encryptOuter(serialized, self.outerIv)

			hmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			serializedBackup = self.backupKey.serialize()
			lb = struct.pack("!H", len(serializedBackup))
			f.write(lb)
			f.write(serializedBackup)
			ll = struct.pack("!I", len(encrypted))
			f.write(ll)
			f.write(encrypted)
			f.write(hmacDigest)

	def encryptOuter(self, plaintext, iv):
		"""
		Pad and encrypt with self.outerKey
		"""
		return self.encrypt(plaintext, iv, self.outerKey)

	def encrypt(self, plaintext, iv, key):
		"""
		Pad plaintext with PKCS#5 and encrypt it.
		"""
		cipher = AES.new(key, AES.MODE_CBC, iv)
		padded = Padding(BLOCKSIZE).pad(plaintext)
		return cipher.encrypt(padded)

	def decryptOuter(self, ciphertext, iv):
		"""
		Decrypt with self.outerKey and unpad
		"""
		return self.decrypt(ciphertext, iv, self.outerKey)

	def decrypt(self, ciphertext, iv, key):
		"""
		Decrypt ciphertext, unpad it and return
		"""
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext)
		unpadded = Padding(BLOCKSIZE).unpad(plaintext)
		return unpadded

	def unwrapKey(self, wrappedOuterKey):
		"""
		Decrypt wrapped outer key using Trezor.
		"""
		ret = self.trezor.decrypt_keyvalue(basics.Magic.unlockNode,
			basics.Magic.unlockKey, wrappedOuterKey,
			ask_on_encrypt=False, ask_on_decrypt=True)
		return ret

	def wrapKey(self, keyToWrap):
		"""
		Encrypt/wrap a key. Its size must be multiple of 16.
		"""
		ret = self.trezor.encrypt_keyvalue(basics.Magic.unlockNode,
			basics.Magic.unlockKey, keyToWrap,
			ask_on_encrypt=False, ask_on_decrypt=True)
		return ret

	def encryptPassword(self, password, groupName):
		"""
		Encrypt a password. Does PKCS#5 padding before encryption.
		Store IV as first block.

		@param password: text to encrypt (combined password+comments)
		@type password: string
		@param groupName: key that will be shown to user on Trezor and
			used to encrypt the password. A string in utf-8
		@type groupName: string
		@returns: bytes
		"""
		rnd = Random.new()
		rndBlock = rnd.read(BLOCKSIZE)
		ugroup = tobytes(groupName)
		password = tobytes(password)
		# minimum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 0    ==> padded that is 16 bytes
		# maximum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 1023 ==> padded that is 1024 bytes
		# plaintext input to trezor.encrypt_keyvalue() must be a multiple of 16
		# trezor.encrypt_keyvalue() throws error on anythin larger than 1024
		# In order to handle passwords+comments larger than 1023 we junk the passwords+comments
		encrypted = b""
		first = True
		splits = [password[x:x+self.MAX_UNPADDED_TREZOR_ENCRYPT_SIZE]
			for x in range(0, len(password), self.MAX_UNPADDED_TREZOR_ENCRYPT_SIZE)]
		for junk in splits:
			padded = Padding(BLOCKSIZE).pad(junk)
			encrypted += self.trezor.encrypt_keyvalue(basics.Magic.groupNode,
				ugroup, padded,
				ask_on_encrypt=False, ask_on_decrypt=first, iv=rndBlock)
			first = False
		ret = rndBlock + encrypted
		# print "Trezor encryption: plain-size =", len(password), ", encrypted-size =", len(encrypted)
		return ret

	def decryptPassword(self, encryptedPassword, groupName):
		"""
		Decrypt a password. First block is IV. After decryption strips PKCS#5 padding.

		@param groupName key that will be shown to user on Trezor and
			was used to encrypt the password. A string in utf-8.
		@returns: string in unicode
		"""
		ugroup = tobytes(groupName)
		iv, encryptedPassword = encryptedPassword[:BLOCKSIZE], encryptedPassword[BLOCKSIZE:]
		# we junk the input, decrypt and reassemble the plaintext
		passwordBytes = b""
		first = True
		splits = [encryptedPassword[x:x+self.MAX_PADDED_TREZOR_ENCRYPT_SIZE]
			for x in range(0, len(encryptedPassword), self.MAX_PADDED_TREZOR_ENCRYPT_SIZE)]
		for junk in splits:
			plain = self.trezor.decrypt_keyvalue(basics.Magic.groupNode,
				ugroup, junk,
				ask_on_encrypt=False, ask_on_decrypt=first, iv=iv)
			first = False
			passwordBytes += Padding(BLOCKSIZE).unpad(plain)
		return normalize_nfc(passwordBytes)

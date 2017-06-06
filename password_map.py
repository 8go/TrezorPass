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
import csv
import os
import os.path
try:
	import cPickle as pickle
except Exception:
	import pickle

from Crypto.Cipher import AES
from Crypto import Random

"""
As clipboard pyperclip would be ideal.
https://pypi.python.org/pypi/pyperclip/
https://github.com/asweigart/pyperclip
The Qt5 port from https://github.com/ilpianista/pyperclip
has not yet be pulled in.
See: https://github.com/asweigart/pyperclip/network
Once available on Qt5, it can be used instead of the std. QApplication.clipboard
"""
# import pyperclip
from PyQt5.QtWidgets import QApplication  # for the clipboard

from trezorlib.client import CallException, PinException

import basics
from encoding import normalize_nfc, tobytes, escape, Padding
from backup import Backup
import processing
import utils

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
		"""
		Add key-value-backup entry
		Appends.
		Duplicates are allowed.
		Empty strings are allowed as key.
		"""
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

	def addGroup(self, groupName, group=None):
		"""
		Add group by name as utf-8 encoded string
		"""
		if groupName in self.groups:
			raise KeyError("Password group already exists")

		if group is None:
			self.groups[groupName] = PasswordGroup()
		else:
			self.groups[groupName] = group

	def deleteGroup(self, groupName):
		if groupName not in self.groups:
			raise KeyError("Password group does not exist")
		del self.groups[groupName]  # delete the group from dictionary

	def copyGroup(self, groupName):
		"""
		Creates a copy of a group by name as utf-8 encoded string
		"""
		if groupName not in self.groups:
			raise KeyError("Password group does not exist")
		return(copy.deepcopy(self.groups[groupName]))

	def createRenamedGroupSecure(self, groupNameOld, groupNameNew):
		groupNew = PasswordGroup()
		rowCount = len(self.groups[groupNameOld].entries)
		for row in range(rowCount):
			key, encPwComments, bkupPw = self.groups[groupNameOld].entries[row]
			try:
				decryptedPwComments = self.decryptPassword(encPwComments, groupNameOld)
			except CallException as e:
				self.settings.mlooger.log("%s" % (e),
					logging.WARNING, "Trezor IO")
				return
			encPwNew = self.encryptPassword(decryptedPwComments, groupNameNew)
			groupNew.addEntry(key, encPwNew, bkupPw)
		return(groupNew)

	def createRenamedGroupFast(self, groupNameOld, groupNameNew):
		groupNew = PasswordGroup()
		groupOld = self.groups[groupNameOld]

		try:
			privateKey = self.backupKey.unwrapPrivateKey()
		except CallException:
			return

		for entry in groupOld.entries:
			key, _, bkupPw = entry
			decryptedPwComments = self.backupKey.decryptPassword(bkupPw, privateKey)
			encPwNew = self.encryptPassword(decryptedPwComments, groupNameNew)
			groupNew.addEntry(key, encPwNew, bkupPw)
		return(groupNew)

	def createRenamedGroup(self, groupNameOld, groupNameNew, moreSecure=True):
		"""
		Creates a copy of a group (given by name as utf-8 encoded string)
		with a new group name.
		This method does not rename any existing group, it just creates an
		additional one with a new name.
		Since the entries inside the group are encrypted
		with the groupName, we cannot simply make a copy.
		We must decrypt with old name and afterwards encrypt
		with new name.
		We provide 2 options:
		- more secure, less convenient: entry-by-entry decryption
		- less secure, more convenient: backup-decryption
		If the group has many entries, each entry would require a 'Confirm'
		press on Trezor. So, in the fast-variant,
		to make it faster, more convenient, more user-friendly
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
		if moreSecure:
			groupNew = self.createRenamedGroupSecure(groupNameOld, groupNameNew)
		else:
			groupNew = self.createRenamedGroupFast(groupNameOld, groupNameNew)
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
			traceback.print_exc()  # prints to stderr
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

			self.backupKey = Backup(self.trezor, noconfirm=self.settings.NArg)
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
			ask_on_encrypt=False, ask_on_decrypt=self.settings.NArg)
		return ret

	def wrapKey(self, keyToWrap):
		"""
		Encrypt/wrap a key. Its size must be multiple of 16.
		"""
		ret = self.trezor.encrypt_keyvalue(basics.Magic.unlockNode,
			basics.Magic.unlockKey, keyToWrap,
			ask_on_encrypt=False, ask_on_decrypt=self.settings.NArg)
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
		first = not self.settings.NArg
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
		first = not self.settings.NArg
		splits = [encryptedPassword[x:x+self.MAX_PADDED_TREZOR_ENCRYPT_SIZE]
			for x in range(0, len(encryptedPassword), self.MAX_PADDED_TREZOR_ENCRYPT_SIZE)]
		for junk in splits:
			plain = self.trezor.decrypt_keyvalue(basics.Magic.groupNode,
				ugroup, junk,
				ask_on_encrypt=False, ask_on_decrypt=first, iv=iv)
			first = False
			passwordBytes += Padding(BLOCKSIZE).unpad(plain)
		return normalize_nfc(passwordBytes)

	def showGroupNames(self):
		for groupName in self.groups:
			print(groupName)

	def printGroup(self, groupName):
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		for key, encPwComments, _ in group.entries:
			decryptedPwComments = self.decryptPassword(encPwComments, groupName)
			lngth = int(decryptedPwComments[0:4])
			decryptedPassword = decryptedPwComments[4:4+lngth]
			decryptedComments = decryptedPwComments[4+lngth:]
			print('key: "%s", password: "%s", comments: "%s"' %
				(key, decryptedPassword, decryptedComments))

	def clipPassword(self, groupName, keyName):
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		matchingKeys = 0
		for key, encPwComments, _ in group.entries:
			if keyName == key:
				matchingKeys += 1
				if matchingKeys == 1:
					decryptedPwComments = self.decryptPassword(encPwComments, groupName)
					lngth = int(decryptedPwComments[0:4])
					decryptedPassword = decryptedPwComments[4:4+lngth]
					# decryptedComments = decryptedPwComments[4+lngth:]
					# pyperclip.copy(decryptedPassword)
					clipboard = QApplication.clipboard()
					clipboard.setText(decryptedPassword)
					self.settings.mlogger.log("Copied password to clipboard.",
						logging.DEBUG, "Clipboard")
		if matchingKeys == 0:
			# pyperclip.copy(decryptedPassword)
			clipboard = QApplication.clipboard()
			clipboard.setText('')
			self.settings.mlogger.log("No key with name '%s' exists in group '%s'. "
				"Clipboard was cleared."
				% (keyName, groupName),
				logging.DEBUG, "Clipboard")
		if matchingKeys > 1:
			self.settings.mlogger.log("%d keys with name '%s' exist in group '%s'. "
				"The first one found was copied to clipboard."
				% (matchingKeys, keyName, groupName),
				logging.DEBUG, "Clipboard")

	def showBoth(self, groupName, keyName=None):
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		matchingKeys = 0
		for key, encPwComments, _ in group.entries:
			if keyName is None or keyName == key:
				matchingKeys += 1
				decryptedPwComments = self.decryptPassword(encPwComments, groupName)
				lngth = int(decryptedPwComments[0:4])
				decryptedPassword = decryptedPwComments[4:4+lngth]
				decryptedComments = decryptedPwComments[4+lngth:]
				if keyName is None:
					print('key: "%s", password: "%s", comments: "%s"' %
						(key, decryptedPassword, decryptedComments))
				else:
					print('password: "%s", comments: "%s"' %
						(decryptedPassword, decryptedComments))
		self.settings.mlogger.log("%d match%s found and printed." %
			(matchingKeys, '' if matchingKeys == 1 else 'es'),
			logging.DEBUG, "Response")

	def showPassword(self, groupName, keyName=None):
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		matchingKeys = 0
		for key, encPwComments, _ in group.entries:
			if keyName is None or keyName == key:
				matchingKeys += 1
				decryptedPwComments = self.decryptPassword(encPwComments, groupName)
				lngth = int(decryptedPwComments[0:4])
				decryptedPassword = decryptedPwComments[4:4+lngth]
				# decryptedComments = decryptedPwComments[4+lngth:]
				if keyName is None:
					print('key: "%s", password: "%s"' % (key, decryptedPassword))
				else:
					print(decryptedPassword)
		self.settings.mlogger.log("%d match%s found and printed." %
			(matchingKeys, '' if matchingKeys == 1 else 'es'),
			logging.DEBUG, "Response")

	def showComments(self, groupName, keyName=None):
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		matchingKeys = 0
		for key, encPwComments, _ in group.entries:
			if keyName is None or keyName == key:
				matchingKeys += 1
				decryptedPwComments = self.decryptPassword(encPwComments, groupName)
				lngth = int(decryptedPwComments[0:4])
				# decryptedPassword = decryptedPwComments[4:4+lngth]
				decryptedComments = decryptedPwComments[4+lngth:]
				if keyName is None:
					print('key: "%s", comments: "%s"' % (key, decryptedComments))
				else:
					print(decryptedComments)
		self.settings.mlogger.log("%d match%s found and printed." %
			(matchingKeys, '' if matchingKeys == 1 else 'es'),
			logging.DEBUG, "Response")

	def showKeys(self, groupName=None):
		matchingGroups = 0
		matchingKeys = 0
		for groupName2 in self.groups:
			if groupName is None or groupName == groupName2:
				matchingGroups += 1
				group = self.groups[groupName2]
				for key, _, _ in group.entries:
					matchingKeys += 1
					if groupName is None:
						print('group: "%s", key: "%s"' % (groupName2, key))
					else:
						print('key: "%s"' % (key))
		self.settings.mlogger.log("%d matching group%s with a total "
			"of %d key%s found and printed." %
			(matchingGroups, '' if matchingGroups == 1 else 's',
			matchingKeys, '' if matchingKeys == 1 else 's'),
			logging.DEBUG, "Response")

	def addEntry(self, groupName, keyName=None, password=None, comments=None):
		"""
		Watch out, there is a method with the same name also for PasswordGroup class
		"""
		if groupName not in self.groups:
			self.groups[groupName] = PasswordGroup()
			self.settings.mlogger.log("New group '%s' created." %
				(groupName),
				logging.DEBUG, "Response")
		if keyName is not None:
			if password is None:
				password = u''
			if comments is None:
				comments = u''
			plainPwComments = ("%4d" % len(password)) + password + comments
			encPw = self.encryptPassword(plainPwComments, groupName)
			bkupPw = self.backupKey.encryptPassword(plainPwComments)
			self.groups[groupName].addEntry(keyName, encPw, bkupPw)
			self.settings.mlogger.log("New record with key '%s' created "
				"and added to group '%s'." %
				(keyName, groupName),
				logging.DEBUG, "Response")

	def renameGroup(self, groupNameOld, groupNameNew, moreSecure=True):
		if groupNameOld not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupNameOld))
		if groupNameNew in self.groups:
			raise KeyError("Error: Password group with name '%s' does already exist."
				% (groupNameNew))
		groupNew = self.createRenamedGroup(groupNameOld, groupNameNew, moreSecure)
		self.deleteGroup(groupNameOld)
		self.addGroup(groupNameNew, groupNew)
		self.settings.mlogger.log("Group '%s' was renamed to '%s'." % (groupNameOld, groupNameNew),
			logging.DEBUG, "GUI IO")

	def updateEntryInGroup(self, groupName, keyName,
		newKey=None, newPassword=None, newComments=None, askUser=False):
		"""
		updates any or all of the 3 values (key, password, comments)
		in the entry specified by groupName and key.
		Entries are not unique, so multiple entries might match.
		@param groupName: identifies the group to update
		@type groupName: string
		@type keyName: string
		@type newKey: string
		@type newPassword: string
		@type newComments: string
		@param askUser: specifies if the user should be promped for input.
			This should only be True in terminal-mode.
			In GUI mode this should be false.
		"""
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		if keyName is None:
			raise KeyError("Key '%s' is not valid."
				% (keyName))
		matches = []  # keep track of positions of matches
		group = self.groups[groupName]
		rowCount = len(group.entries)
		for row in reversed(range(rowCount)):  # Reverse countdown
			key, _, _ = group.entries[row]
			if keyName == key:
				matches.append(row)
		if len(matches) == 0:
			raise KeyError("Warning: No match found for key '%s'. Nothing updated."
				% (keyName))
		if len(matches) == 1:
			# get the old data
			key, encPwComments, _ = group.entries[matches[0]]
			decryptedPwComments = self.decryptPassword(encPwComments, groupName)
			lngth = int(decryptedPwComments[0:4])
			plainPw = decryptedPwComments[4:4+lngth]
			plainComments = decryptedPwComments[4+lngth:]
			# update elements
			if newKey is not None:
				key = newKey
			if newPassword is not None:
				plainPw = newPassword
			if newComments is not None:
				plainComments = newComments
			plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments
			encPw = self.encryptPassword(plainPwComments, groupName)
			bkupPw = self.backupKey.encryptPassword(plainPwComments)
			group.updateEntry(matches[0], key, encPw, bkupPw)
			self.settings.mlogger.log("Entry in row %d was updated." % (matches[0]),
				logging.DEBUG, "Response")
			return
		# more than 1 match found
		if not askUser:
			raise KeyError("Warning: %d matches found for key '%s'. "
				"Don't know which one to update. Hence, nothing updated."
				% (len(matches), keyName))
		# multiple matches and askUser is True
		self.settings.mlogger.log("%d matches found for key '%s'. We now go "
			"through each match one by one, so you can decide which "
			"one(s) to update." %
			(len(matches), keyName),
			logging.DEBUG, "Response")
		print("%d matches found for key '%s'. We now go "
			"through each match one by one, so you can decide which "
			"one(s) to update." %
			(len(matches), keyName))
		ii = 0
		for row in matches:
			ii += 1
			# get the old data
			key, encPwComments, _ = group.entries[row]
			decryptedPwComments = self.decryptPassword(encPwComments, groupName)
			lngth = int(decryptedPwComments[0:4])
			plainPw = decryptedPwComments[4:4+lngth]
			plainComments = decryptedPwComments[4+lngth:]
			# ask user
			print('Entry %d of %d: key: "%s", password: "%s", comments: "%s"' %
				(ii, len(matches), key, plainPw, plainComments))
			while True:
				myinput = utils.input23(u"Update this entry? Y(es)/N(o)/Q(uit) ")
				if (myinput.upper() == 'Y' or myinput.upper() == 'YES' or
					myinput.upper() == 'N' or myinput.upper() == 'NO' or
					myinput.upper() == 'Q' or myinput.upper() == 'QUIT'):
					break
			if myinput.upper() == 'Q' or myinput.upper() == 'QUIT':
				return
			if myinput.upper() == 'N' or myinput.upper() == 'NO':
				continue
			# update elements
			if newKey is not None:
				key = newKey
			if newPassword is not None:
				plainPw = newPassword
			if newComments is not None:
				plainComments = newComments
			plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments
			encPw = self.encryptPassword(plainPwComments, groupName)
			bkupPw = self.backupKey.encryptPassword(plainPwComments)
			group.updateEntry(row, key, encPw, bkupPw)
			self.settings.mlogger.log("Entry in row %d was updated." % (row),
				logging.DEBUG, "Response")

	def deletePasswordEntryBatch(self, groupName, keyName=None):
		"""
		Batch: it wil remove ALL matches without asking the user
		"""
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		group = self.groups[groupName]
		matchingKeys = 0
		rowCount = len(group.entries)
		for row in reversed(range(rowCount)):  # Reverse countdown
			key, _, _ = group.entries[row]
			if keyName is None or keyName == key:
				matchingKeys += 1
				group.removeEntry(row)
				self.settings.mlogger.log('Removing row %d with key "%s".' %
					(row, key), logging.DEBUG, "Response")
		grpdeltxt = ''
		if keyName is None:
			del self.groups[groupName]  # delete the group from dictionary
			grpdeltxt = ' 1 group deleted.'
		self.settings.mlogger.log("%d key match%s found and deleted.%s" %
			(matchingKeys, '' if matchingKeys == 1 else 'es', grpdeltxt),
			logging.DEBUG, "Response")

	def deletePasswordEntry(self, groupName, keyName=None, askUser=False):
		"""
		Deletes any or all of the 3 values (key, password, comments)
		in the entry specified by groupName and key.

		If no key is given the whole group will be deleted.
		If a key is given it will look for the matching entries.
		Entries are not unique, so multiple entries might match.
		If askUser is true it will ask the user which entries to
		delete thru terminal interaction.
		@param groupName: identifies the group to update
		@type groupName: string
		@type keyName: string
		@type newKey: string
		@param askUser: specifies if the user should be promped for input.
			This should only be True in terminal-mode.
			In GUI mode this should be false.
		"""
		if groupName not in self.groups:
			raise KeyError("Error: Password group with name '%s' does not exist."
				% (groupName))
		if keyName is None:
			self.deletePasswordEntryBatch(groupName, keyName)
			return
		matches = []  # keep track of positions of matches
		group = self.groups[groupName]
		rowCount = len(group.entries)
		for row in reversed(range(rowCount)):  # Reverse countdown
			key, _, _ = group.entries[row]
			if keyName == key:
				matches.append(row)
		if len(matches) == 0:
			raise KeyError("Warning: No match found for key '%s'. Nothing deleted."
				% (keyName))
		if len(matches) == 1:
			group.removeEntry(matches[0])
			self.settings.mlogger.log('Entry in row %d with key "%s" was deleted.' %
				(matches[0], keyName), logging.DEBUG, "Response")
			return
		# more than 1 match found
		if not askUser:
			raise KeyError("Warning: %d matches found for key '%s'. "
				"Don't know which one to delete. Hence, nothing deleted."
				% (len(matches), keyName))
		# multiple matches and askUser is True
		self.settings.mlogger.log("%d matches found for key '%s'. We now go "
			"through each match one by one, so you can decide which "
			"one(s) to delete." %
			(len(matches), keyName),
			logging.DEBUG, "Response")
		print("%d matches found for key '%s'. We now go "
			"through each match one by one, so you can decide which "
			"one(s) to update." %
			(len(matches), keyName))
		ii = 0
		for row in matches:
			ii += 1
			# get the old data
			key, encPwComments, _ = group.entries[row]
			decryptedPwComments = self.decryptPassword(encPwComments, groupName)
			lngth = int(decryptedPwComments[0:4])
			plainPw = decryptedPwComments[4:4+lngth]
			plainComments = decryptedPwComments[4+lngth:]
			# ask user
			print('Entry %d of %d: key: "%s", password: "%s", comments: "%s"' %
				(ii, len(matches), key, plainPw, plainComments))
			while True:
				myinput = utils.input23(u"Delete this entry? Y(es)/N(o)/Q(uit) ")
				if (myinput.upper() == 'Y' or myinput.upper() == 'YES' or
					myinput.upper() == 'N' or myinput.upper() == 'NO' or
					myinput.upper() == 'Q' or myinput.upper() == 'QUIT'):
					break
			if myinput.upper() == 'Q' or myinput.upper() == 'QUIT':
				return
			if myinput.upper() == 'N' or myinput.upper() == 'NO':
				continue
			# delete entry
			group.removeEntry(row)
			self.settings.mlogger.log('Entry in row %d with key "%s" was deleted.' %
				(row, key), logging.DEBUG, "Response")

	def importCsv(self, fname):
		"""
		See also the method with the same name in Dialog class in dialogs.py

		@param fname: name of CSV file
		@type fname: string
		@returns list of srings reflecting the list of NEW group names
			that were ADDED to the known group names by reading
			from the CSV file
		"""
		if not os.path.isfile(fname):
			raise KeyError('File "%s" does not exist, is not a proper file, '
				'or is a directory. Aborting.' % fname)
		if not os.access(fname, os.R_OK):
			raise KeyError('File "%s" is not readable. Aborting.' % fname)
		# list to track all new group names read from the CSV file,
		# that did not exist before
		listOfAddedGroupNames = []
		with open(fname, "r") as f:
			csv.register_dialect("escaped", doublequote=False, escapechar='\\')
			reader = csv.reader(f, dialect="escaped")
			for csvEntry in reader:
				# self.settings.mlogger.log("CSV Entry: len=%d 0=%s" % (len(csvEntry), csvEntry[0]),
				# 	logging.DEBUG, "CSV import")
				# self.settings.mlogger.log("CSV Entry: 0=%s, 1=%s, 2=%s, 3=%s" %
				# 	(csvEntry[0], csvEntry[1], csvEntry[2], csvEntry[3]), logging.DEBUG,
				# 	"CSV import")
				try:
					groupName = normalize_nfc(csvEntry[0])
					key = normalize_nfc(csvEntry[1])
					plainPw = normalize_nfc(csvEntry[2])
					plainComments = normalize_nfc(csvEntry[3])
				except Exception as e:
					raise IOError("Critical Error: Could not import CSV file. "
						"CSV Entry: len=%d (should be 4) element[0]=%s. (%s)" %
							(len(csvEntry), csvEntry[0], e))

				groupNames = self.groups.keys()
				if groupName not in groupNames:  # groups are unique
					self.addGroup(groupName)
					listOfAddedGroupNames.append(groupName)

				if len(plainPw) + len(plainComments) > basics.MAX_SIZE_OF_PASSWDANDCOMMENTS:
					self.settings.mlogger.log("Password and/or comments too long. "
						"Combined they must not be larger than %d." % basics.MAX_SIZE_OF_PASSWDANDCOMMENTS, logging.NOTSET,
						"CSV import")
					return
				group = self.groups[groupName]
				plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments
				encPw = self.encryptPassword(plainPwComments, groupName)
				bkupPw = self.backupKey.encryptPassword(plainPwComments)
				group.addEntry(key, encPw, bkupPw)  # keys are not unique, multiple items with same key are allowed

		self.settings.mlogger.log("TrezorPass has finished importing CSV file "
			"from \"%s\" into \"%s\"." % (fname, self.settings.dbFilename), logging.INFO,
			"CSV import")
		return(listOfAddedGroupNames)

	def exportCsv(self, fname):
		"""
		See also the method with the same name in Dialog class in dialogs.py

		@param fname: name of CSV file
		@type fname: string
		@returns nothing
		"""
		backupKey = self.backupKey
		try:
			privateKey = backupKey.unwrapPrivateKey()
		except CallException:
			return

		with open(fname, "w") as f:
			csv.register_dialect("escaped", doublequote=False, escapechar='\\')
			writer = csv.writer(f, dialect="escaped")
			sortedGroupNames = sorted(self.groups.keys())
			for groupName in sortedGroupNames:
				group = self.groups[groupName]
				for entry in group.entries:
					key, _, bkupPw = entry
					decryptedPwComments = backupKey.decryptPassword(bkupPw, privateKey)
					lngth = int(decryptedPwComments[0:4])
					password = decryptedPwComments[4:4+lngth]
					comments = decryptedPwComments[4+lngth:]
					# if we don't escape than the 2-letter string '"\' will
					# lead to an exception on import
					csvEntry = (escape(groupName),
						escape(key),
						escape(password),
						escape(comments))
					# all 4 elements in the 4-tuple are of type string
					# Py2-vs-Py3: writerow() in Py2 implements on 7-bit unicode
					# In py3 it implements full unicode.
					# That means if there is a foreign character, writerow()
					# in Py2 reports the exception:
					# "UnicodeEncodeError: 'ascii' codec can't encode character u'\xxx' in position xx
					# In Py2 we need to convert it back to bytes!
					if sys.version_info[0] < 3:  # Py2-vs-Py3:
						# the byte-conversion un-escapes, so we have to escape again!
						csvEntry = (escape(tobytes(groupName)),
							escape(tobytes(key)),
							escape(tobytes(password)),
							escape(tobytes(comments)))
					writer.writerow(csvEntry)

		self.settings.mlogger.log("TrezorPass has finished exporting CSV file "
			"from \"%s\" to \"%s\"." % (self.settings.dbFilename, fname), logging.INFO,
			"CSV export")

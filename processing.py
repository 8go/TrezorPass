from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
from pprint import pprint

from dialogs import InitializeDialog
import backup
from encoding import normalize_nfc
from password_map import PasswordGroup

"""
This file holds the main business logic.
It should be shared by the GUI mode and the Terminal mode.
"""


def initializeStorage(trezor, pwMap, settings):
	"""
	Initialize new encrypted password file, ask for master passphrase.

	Initialize RSA keypair for backup, encrypt private RSA key using
	backup passphrase and Trezor's cipher-key-value system.

	Makes sure a session is created on Trezor so that the passphrase
	will be cached until disconnect.

	@param trezor: Trezor client
	@param pwMap: PasswordMap where to put encrypted backupKeys
	@param settings: Settings object to store password database location
	"""
	dialog = InitializeDialog()
	if settings.passphrase() is not None:
		dialog.setPw1(settings.passphrase())
		dialog.setPw2(settings.passphrase())

	if not dialog.exec_():
		sys.exit(4)

	masterPassphrase = dialog.pw1()
	trezor.prefillPassphrase(masterPassphrase)
	backupkey = backup.Backup(trezor)
	backupkey.generate()
	pwMap.backupKey = backupkey
	settings.dbFilename = dialog.pwFile()
	settings.FArg = dialog.pwFile()
	settings.store()


def updatePwMapFromV1ToV2(pwMap, settings):
	"""
	Update the pwMap from v1 (only password) to v2 (password and comments).
	"""
	backupKey = pwMap.backupKey
	try:
		privateKey = backupKey.unwrapPrivateKey()
	except Exception as e:
		settings.mlogger.log("Error getting key for doing backup (%s)." % (e),
			logging.ERROR, "TrezorPass database")
		return

	for groupName in pwMap.groups.keys():
		group = pwMap.groups[groupName]
		for entry in group.entries:
			key, encryptedPw, bkupPw = entry
			plainPw = backupKey.decryptPassword(bkupPw, privateKey)
			plainPwComments = ("%4d" % len(plainPw)) + plainPw
			encPw = pwMap.encryptPassword(plainPwComments, groupName)
			bkupPw = pwMap.backupKey.encryptPassword(plainPwComments)
			idx = group.entries.index(entry)
			group.updateEntry(idx, key, encPw, bkupPw)
	pwMap.save(settings.dbFilename)
	settings.mlogger.log("Trezorpass database \"%s\" successfully "
		"updated from version 1 to version 2." % settings.dbFilename, logging.NOTSET,
		"TrezorPass database")


def migrateUnpickledDataFromPy2ToPy3(groupsDict, settings):
	"""
	Takes an instance such as PasswordMap.groups
	which is a dictionary of PasswordGroup instances.
	Each PasswordGroup instance an object with entries
	which are lists of tuples.
	Only works in Python3, Py3.
	"""
	if sys.version_info[0] < 3:  # Py2-vs-Py3:
		raise RuntimeError(u"This code should only have been called with Python 3 or higher.")
	settings.mlogger.log("Trying to migrate TrezorPass database \"%s\" "
		"from Python 2 ro Python3." % settings.dbFilename, logging.DEBUG,
		"TrezorPass database")
	print('zzz3',groupsDict)
	groupsNew = {}  # PasswordGroup()
	ii = 0
	for groupName in groupsDict:
		ii += 1
		print('groupName %s' % (groupName))
		pwGroup = groupsDict[groupName]
		print('\n pwGroup %s %s' % (pwGroup, type(pwGroup)))
		print('\n groupName %s %s' % (groupName, type(groupName)))  # Py2: str, Py3: bytes
		groupsNew[normalize_nfc(groupName)] = PasswordGroup()
		print('groupsNew')
		pprint(groupsNew)
		pprint(dict(groupsNew))
		print('groupNew')
		pprint(groupsNew[normalize_nfc(groupName)])
		pprint(vars(groupsNew[normalize_nfc(groupName)]))
		print('pwGroup')
		pprint(vars(pwGroup))

		mydict = pwGroup.__dict__
		
		print('\n mydict %s %s\n' % (mydict, type(mydict)))
		for instvarkey in mydict:
			print('\n instvarkey %s %s\n' % (instvarkey, type(instvarkey)))  # bytes
			instvarval = mydict[instvarkey]
			print('\n instvarval %s %s\n' % (instvarval, type(instvarval)))  # list
			for triple in instvarval:
				print('\n triple %s %s\n' % (triple, type(triple)))  # tuple
				key, encPw, bkupPw = triple
				groupsNew[normalize_nfc(groupName)].addEntry(normalize_nfc(key), encPw, bkupPw)
				print('groupNew')
				pprint(groupsNew[normalize_nfc(groupName)])
				pprint(vars(groupsNew[normalize_nfc(groupName)]))
	print("\n %d groups migrated." % (ii))

	#pprint('zzz5',groupsNew)
	return(groupsNew)

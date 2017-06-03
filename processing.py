from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging

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


def migrateUnpickledDataFromPy2ToPy3(groupsDictPy2, settings):
	"""
	Takes an instance such as PasswordMap.groups
	which is a dictionary of PasswordGroup instances.
	Each PasswordGroup instance is an object with entries
	which are lists of tuples.
	Only works in Python3, Py3.
	Migrates unpickled pwdb data of groups from Py2 to Py3 format.
	Takes an unpickled pwdb groups object in Py2 and
	returns an unpickled pwdb groups object in Py3 format.

	This code can be removed once Py2 is no longer supported.

	Case 1:
	Py2 unpickling a Py2-pickled pwdb file sees the following:
	groups = {'some groupname': <password_map.PasswordGroup object at 0x0fd06a4abed0>, ...}
	with password_map.PasswordGroup being seen as:
	{'entries': [('some username',
		'$-WA\xaf\x04z\xff\n\x0f\xb1\x1cTo\xd8\xc2\xe6\xab\xd9\x96%\xce\x90\xb6\x82\x8e-\xb62A\x1d\xc5',
		'"T06\xea\xa5\x83qP\x0f5\xd0~\xc4\x83Fb\x8ei\x08\xb6\xe0\xa0\x91\x88d\x14I\x9c\xae\xbd\x04\xb8T!6\x1d\xb3\xcd\xd2\x08j\xc1\xaf\xce\xdb\xe7\x8cq^\xa1`\x93\xf1\xeb\xd7\xf1X\x80\x80\xdb8Y\xca{\xa5s\x82"Z\x9b}\xba\xaa\x0c>P~\xbd1\xde\xaaM\xed]\x9eq\x13PI\xd1\x1f\x9fRc\xa4\x15\xdd\xd2\xa8\xe3d\xcf\xe3w\xd5\xf5\x04\xbdR\x86\xc9\xb7\x97\xec\xe1@\xa7\x08\xf1\xef)\x93\xa0n\xcb\xaaH2\xb8%\xb8\'\xd8\x06\xd0\xb4*\xe0\xdb}\x91\xa1\xd4J\\+\r\xb8\xe6a\xba\xdf\xa0\xe2\xbe\xeb5\xbf\xdfh\xae\xd9\x83\x93lT\xcc\x07\x95$@\x1c@\x89R\xe9\xf1\xf0+w\x07i~/\x17^\t\xceVuU\x11\x12\x1c\x90*qt\t\x06_q\xa9\x8c\x85\x99\x11\x98v\xe18\xe3\x19\xcf\xaa\x9a7\xa0qk\x00\x8d\xdbh\xf0\x90\x08\xac\x14k?\x1a\xcc>\x92o\xd1\xf6\xfbK&\xc8\x88\x01\x8d\xad<\xeba\xff\xa5\x0eH\xf8r=]\xb4TT\xd1\xa0\xd6P\x98Gl|\xec\xcbpo\x90k:\xf1\x8d\xcf\xe7\xb5S1\xbd\x93\x15\xd2\xb3@G\x1f\x8eIkz\xfd&\x1bb\x0b\xa5\xac\xa7L\r\xf3\x0e\xfb\xd9\xa0\xf6@\xc5\xa9\xd3Dexi;GYk\xdc\xeb\xa8\x11\xca\x0c\x88X\x9e{I\xc1\xeb\xd3\x8e]\x81\xbe\xcd\x10\x1b\xea\x04\xb1h\x88\xe6\x9f\xcfz\x86W_1*MQ\x16\x9c\x9a=\xf3\x96\xb8\x8d\xad\nEI\x14s0\xcbZ\xc6\xda\r\xbb\n\xe0\xdf\xfac\x84\xb4y\xf0\xa63n\xf9H/V\xbe\xd3t\x85\xfe\xcb\xb7L>\x04U\xb0"\xbd\x87n\xc1)P\xeeJ\xbf\xb7\xbb\xe9\xb5)(\xf7D\x89\xe9Z\x97T\xb1x\x19/\xb9\x08\x1f\xd7+?\xeaTg_\xd2\x85\xc6\x86\xd87\t3V\xfeu\x03r\xb7g\xb9\x90\xa5\xa0\xcf=:\xe7\x19\xf9S\xa4\x16\x88\xa1~"\xd9\x05K\x9b2\x1e\x04Q\x8c\xf9\xc1\x02\x865\x8b\xde\xc9\xe2\x1f\xf1\xfc\xf4S\xff\xc8\x8e\x11\xc0\x95\xe8\x0b\xe0\x0e\x16'), ...]}
	So, for Py2 this works: tuple = pwMap.groups['some groupname'].entries[0]
	Specifically, group.entries exists as expected.
	All items like groupname, the 3 items in the tuple are of type 'str'.
	vars(self.groups[self.groups.keys()[0]]): works
	dict(self.groups[self.groups.keys()[0]]): fails, TypeError: 'PasswordGroup' object is not iterable

	Case 2:
	Py3 unpickling a Py2-pickled pwdb file sees the following:
	groups = {b'some groupname': <password_map.PasswordGroup object at 0x0fd06a4abed0>, ...}
	with password_map.PasswordGroup being seen as:
	{b'entries': [(b'some username',
		b'\xb7\x877\xb3\xf4\xaf\xa0\x91\xec\x7fOlr\x8fn\xf3\xed\x8b\x1a\x15\xc7\xc5\x14\xc7\xeb\xb2[\xb5l\xab\xe9\xc9\x97\x1b\xff\xac\x1a\xd1\xc3\xce\x1bXTH\x89\xef\x00Y',
		b'_\xc2\x94B\x07]\x13\xc4\xaa)K\xb34`\xf5\xd9\xc0g\xefqX6\xa3\x95T5\\\xa9\x1eX\x19$\x02G\xaf8\x98\'\x05\xcc\xae\xb5^m\x0f\x92\x94\xcfI\xb9\xa1\xd2\xbfe2\x00E\xca\xf5\x84\xea\xcc\xe9\xaf+\xad\x90a\x06\x00Z7^\xe6\xc1EOn\xa5\x10mN\xf6\xdd\x92\x13\xe6[Ba\xe2\xa2iY2\x05\xc6\xc4\x9b\\^\xef"\x19O\xa3\xcd\xe4\xc5\x9eT\x80s\x81\xee\xc2$\x92\xfdQ\x86\xaf\xcf\x16\xb0<\xc3j\'\xf0G\x01\xa9\xcf;\xb1l\xcf\xcd4\xc6\x0cN\xba\xe4pK\xa4y\xf7\x01\xe8+v\x80\xa8<\xf8\x9f\xb4d\xb7\xe0\xb5\xbc^6\xc9J\\\xe3\x91\x9a\xa5\x08)\x0b\x958YI\xb5\xb7(W\xa5\xf8G\x02\x0f\x9c\x8dE\x0c*\\\xc9\x07\xaaW\xe3>\x93\x7f\x87\xe5\xff\xfe\x16G\xcf\x90\xd4\xd6?\xf0\x16\xa4\x93\xce\xd8\x9c\xf1\xff\x81`\xbf"W\xee\xfb\\[\xe5\x13\xd8[R\xec\xd2\xc6Erh\xdf\xdd\xebX\x8f\xf4[\x0e\x9d\xea\xa1\t;\xaf\x81\x8b\xc0\xb4\xa77\xde8v\xe4\x94\xf0\x87(\xa4\x87\x99\x9dCd\x08^\xb8\x84\x83E\x1a[/\xda\xc82,\xb4o\xea\x1cSI_\xb3\xd0t<\xe1\xea\xbb\x9c\n9IOuf\x95A\xec\xa7\xfa2>$\xb4\xea0\xcd\xc3\xa3\x1e\t&\x8cI\xfdqN0\xd1J\xebU>\xf1x\xc4\xb2\x0en\x8c\xaf\\B5b\xc9\xce\x87\xb4\x15\xbe\xe8e0\xe0\xa5@\x01Ib\xc3l#Z\xc7o%\xd9C\xac\xee\x16\xe1\xee\xba\xc3\xbe\x96\xdc\xba\xbc\xc4w\xb1\x7f\x02\x95\xcf(skt/\x84\x0b1\xb7\x14\\\xc6\x9e\xb4c\xcb\xc8\xb8\x8bY\'\x1a\xf6\xa35^\x1f\xba\x9c\x93\x8c\xa15\xbfdZ0\n\x9en{\xc0\xb5\x02>N\xee\xb2c\xc4\xcf\xb6\xc1Ot\xd7\x00\x0c\xb7\xc4x\x1dt\x92\'T*\xedW\xe7s\xed\x95J\x0f\xd8**"\xf4s\x1b\x1fK2\n\xb0\x8f\xb1P\xff\xa0\xe0\xdd\xd6\x94\x94ed\x1d\x07\xd7G\x99B]S\xa2\x8d\xe3\xd1\xa2Q`\xd6\x9b\x83'), ...]}
	So, for Py3 this leads to an exception: tuple = pwMap.groups['some groupname'].entries[0]
	Specifically, group.entries does NOT exists.
	All items like groupname, the 3 items in the tuple are of type 'bytes'.
	(That is because we read in binary mode. Reading in ASCII mde would fail as pwdb is not an ASCII file.)
	vars(self.groups[list(self.groups.keys())[0]]): works
	dict(self.groups[list(self.groups.keys())[0]]): fails, TypeError: 'PasswordGroup' object is not iterable

	Case 3:
	Py3 unpickling a Py3-pickled pwdb file sees the following:
	groups = {'some groupname': <password_map.PasswordGroup object at 0x0fd06a4abed0>, ...}
	with password_map.PasswordGroup being seen as:
	{'entries': [('some username',
		b'\xb7\x877\xb3\xf4\xaf\xa0\x91\xec\x7fOlr\x8fn\xf3\xed\x8b\x1a\x15\xc7\xc5\x14\xc7\xeb\xb2[\xb5l\xab\xe9\xc9\x97\x1b\xff\xac\x1a\xd1\xc3\xce\x1bXTH\x89\xef\x00Y',
		b'_\xc2\x94B\x07]\x13\xc4\xaa)K\xb34`\xf5\xd9\xc0g\xefqX6\xa3\x95T5\\\xa9\x1eX\x19$\x02G\xaf8\x98\'\x05\xcc\xae\xb5^m\x0f\x92\x94\xcfI\xb9\xa1\xd2\xbfe2\x00E\xca\xf5\x84\xea\xcc\xe9\xaf+\xad\x90a\x06\x00Z7^\xe6\xc1EOn\xa5\x10mN\xf6\xdd\x92\x13\xe6[Ba\xe2\xa2iY2\x05\xc6\xc4\x9b\\^\xef"\x19O\xa3\xcd\xe4\xc5\x9eT\x80s\x81\xee\xc2$\x92\xfdQ\x86\xaf\xcf\x16\xb0<\xc3j\'\xf0G\x01\xa9\xcf;\xb1l\xcf\xcd4\xc6\x0cN\xba\xe4pK\xa4y\xf7\x01\xe8+v\x80\xa8<\xf8\x9f\xb4d\xb7\xe0\xb5\xbc^6\xc9J\\\xe3\x91\x9a\xa5\x08)\x0b\x958YI\xb5\xb7(W\xa5\xf8G\x02\x0f\x9c\x8dE\x0c*\\\xc9\x07\xaaW\xe3>\x93\x7f\x87\xe5\xff\xfe\x16G\xcf\x90\xd4\xd6?\xf0\x16\xa4\x93\xce\xd8\x9c\xf1\xff\x81`\xbf"W\xee\xfb\\[\xe5\x13\xd8[R\xec\xd2\xc6Erh\xdf\xdd\xebX\x8f\xf4[\x0e\x9d\xea\xa1\t;\xaf\x81\x8b\xc0\xb4\xa77\xde8v\xe4\x94\xf0\x87(\xa4\x87\x99\x9dCd\x08^\xb8\x84\x83E\x1a[/\xda\xc82,\xb4o\xea\x1cSI_\xb3\xd0t<\xe1\xea\xbb\x9c\n9IOuf\x95A\xec\xa7\xfa2>$\xb4\xea0\xcd\xc3\xa3\x1e\t&\x8cI\xfdqN0\xd1J\xebU>\xf1x\xc4\xb2\x0en\x8c\xaf\\B5b\xc9\xce\x87\xb4\x15\xbe\xe8e0\xe0\xa5@\x01Ib\xc3l#Z\xc7o%\xd9C\xac\xee\x16\xe1\xee\xba\xc3\xbe\x96\xdc\xba\xbc\xc4w\xb1\x7f\x02\x95\xcf(skt/\x84\x0b1\xb7\x14\\\xc6\x9e\xb4c\xcb\xc8\xb8\x8bY\'\x1a\xf6\xa35^\x1f\xba\x9c\x93\x8c\xa15\xbfdZ0\n\x9en{\xc0\xb5\x02>N\xee\xb2c\xc4\xcf\xb6\xc1Ot\xd7\x00\x0c\xb7\xc4x\x1dt\x92\'T*\xedW\xe7s\xed\x95J\x0f\xd8**"\xf4s\x1b\x1fK2\n\xb0\x8f\xb1P\xff\xa0\xe0\xdd\xd6\x94\x94ed\x1d\x07\xd7G\x99B]S\xa2\x8d\xe3\xd1\xa2Q`\xd6\x9b\x83'), ...]}
	So, for Py3 this works again: tuple = pwMap.groups['some groupname'].entries[0]
	Specifically, group.entries exists.
	Groupname, and 0-element in tuple (key) are of type 'str' (unicode).
	1-element (encPwCmt) and 2-element (encBackup) in the tuple are of type 'bytes'.

	Case 4:
	Py2 unpickling a Py3-pickled pwdb file sees the following:
		Error: unsupported pickle protocol: 4
		This is not supported. Py2 cannot open a Py3 pickled pwdb file.

	@params groupsDictPy2: un unpickled password groups instance
	@type groupsDictPy2: a Py2 version of unpickled dictionary {} of PasswordGroup instances
	@returns: a dictionary {} of PasswordGroup instances apt for Py3
	"""
	if sys.version_info[0] < 3:  # Py2-vs-Py3:
		raise RuntimeError(u"This code should only have been called with Python 3 or higher.")
	settings.mlogger.log("Trying to migrate TrezorPass database \"%s\" "
		"from Python 2 to Python3." % settings.dbFilename, logging.DEBUG,
		"TrezorPass database")
	groupsDictPy3 = {}  # dictionary of PasswordGroup() instances
	ii = 0
	for groupName in groupsDictPy2:
		ii += 1
		# groupName is of type bytes
		pwGroup = groupsDictPy2[groupName]
		# pwGroup is of type PasswordGroup
		# create and add a new empty group in Py3, convert groupname to type string.
		groupsDictPy3[normalize_nfc(groupName)] = PasswordGroup()
		# settings.mlogger.log("Password group %d read: \n%s" % (ii, vars(pwGroup)),
		# 	logging.DEBUG, "TrezorPass database migration")
		# since .entries member var does not exist, we use __dict__ to get to the data
		mydict = pwGroup.__dict__
		# mydict has key b'entries', the corresponding value is of type list (of tuples)
		# there is only 1 key in the mydict dictionary: key b'entries'
		for instvarkey in mydict:
			# type(instvarkey) returns bytes
			instvarval = mydict[instvarkey]
			# type(instvarval) returns list
			for triple in instvarval:
				# type(triple) returns tuple
				# all 3 entries in tuple are of type 'bytes'
				# entry 0 is the key, and we want that to be a 'string' (unicode)
				# because that is displayed (e.g. 'login', or strings with foreign characters)
				# entry 1 and 2 are encrypted values of pw+comments and backupPw.
				# Since they are encrypted we want those 2 to remain of type 'bytes'
				key, encPw, bkupPw = triple
				# add tuple to Py3 group
				groupsDictPy3[normalize_nfc(groupName)].addEntry(normalize_nfc(key), encPw, bkupPw)
		# settings.mlogger.log("Password group %d written: \n%s" %
		# 	(ii, vars(groupsDictPy3[normalize_nfc(groupName)])), logging.DEBUG,
		# 	"TrezorPass database migration")
	settings.mlogger.log("%d password groups have been migrated "
		"from Python 2 to Python 3." % (ii), logging.DEBUG,
		"TrezorPass database migration")
	return(groupsDictPy3)


def migrateToUnicode(groupsDictBytes, settings):
	"""
	In an old version of TrezorPass groupName and key (0-element of tuple)
	were in Py2 type 'str' (not in 'unicode') and did not allow
	foreign characters. To fix this when we read the pwdb file
	we must migrate from Py2 'str' to 'unicode'.

	Takes an instance such as PasswordMap.groups
	which is a dictionary of PasswordGroup instances.
	Each PasswordGroup instance is an object with entries
	which are lists of tuples.

	Migrated unpickled pwdb data of groups from Py2 to Py3 format.
	Takes an unpickled pwdb groups object in Py2 and
	returns an unpickled pwdb groups object in Py3 format.

	@params groupsDictBytes: un unpickled password groups instance
	@type groupsDictBytes: a bytes (Py3) or str (py2) version of unpickled dictionary {} of PasswordGroup instances
	@returns: a dictionary {} of PasswordGroup instances with groupName and key in str (Py3) or unicode (Py2)
	"""
	groupsDictStr = {}  # dictionary of PasswordGroup() instances
	ii = 0
	for groupName in groupsDictBytes:
		ii += 1
		# groupName is of type bytes
		pwGroup = groupsDictBytes[groupName]
		# pwGroup is of type PasswordGroup
		# create and add a new empty group in Py3, convert groupname to type string.
		groupsDictStr[normalize_nfc(groupName)] = PasswordGroup()
		# settings.mlogger.log("Password group %d read: \n%s" % (ii, normalize_nfc(groupName)),
		# 	logging.DEBUG, "TrezorPass database migration")
		for entry in pwGroup.entries:
			key, encPw, bkupPw = entry
			# add tuple to Py3 group
			groupsDictStr[normalize_nfc(groupName)].addEntry(normalize_nfc(key), encPw, bkupPw)
	settings.mlogger.log("%d password groups have been migrated "
		"to unicode." % (ii), logging.DEBUG,
		"TrezorPass database migration")

	return(groupsDictStr)

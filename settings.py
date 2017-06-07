from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import getopt
import os.path

from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QT_VERSION_STR, QSettings
from PyQt5.Qt import PYQT_VERSION_STR

import basics
import encoding
from utils import BaseSettings, BaseArgs

"""
This is code that should be adapted to your applications.
This code implements Settings and Argument parsing.

Classes BaseSettings and BaseArgs from utils.py
should be subclassed her as Settings and Args.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


class Settings(BaseSettings):
	"""
	Placeholder for settings
	Settings such as command line options, GUI selected values,
	user input, etc.
	"""

	def __init__(self, logger=None, mlogger=None):
		"""
		@param logger: holds logger for where to log info/warnings/errors
			If None, a default logger will be created.
		@type logger: L{logging.Logger}
		@param mlogger: holds mlogger for where to log info/warnings/errors
			If None, a default mlogger will be created.
		@type mlogger: L{utils.MLogger}
		"""
		super(Settings, self).__init__(logger, mlogger)
		self.dbFilename = None  # pwdb file name
		self.qsettings = QSettings(u"ConstructibleUniverse", u"TrezorPass")
		fname = self.qsettings.value(u"database/filename")
		# returns None or unicode string
		if fname is not None:
			self.dbFilename = encoding.normalize_nfc(fname)
		self.TArg = False  # Terminal mode
		self.NArg = False  # noconfirm mode
		self.PArg = None  # passphrase
		self.QArg = False  # set pwdb file as Defaut
		self.FArg = None  # pwdb file name, None or a string

		self.AArg = False  # add flag
		self.CArg = False  # clip flag
		self.SArg = False  # show
		self.OArg = False  # showcomments
		self.BArg = False  # showboth
		self.EArg = False  # showkeys
		self.XArg = False  # showgroups
		self.DArg = False  # delete
		self.RArg = False  # rename group
		self.UArg = False  # update password entries
		self.YArg = None  # importcsv
		self.ZArg = None  # exportcsv
		self.WArg = None  # password/secret, None or a string
		self.MArg = None  # comments, None or a string
		self.GArg = None  # group name, None or a string
		self.KArg = None  # key name, None or a string
		self.n0Arg = None  # new group name, None or a string
		self.n1Arg = None  # new key name, None or a string
		self.n2Arg = None  # new password, None or a string
		self.n3Arg = None  # new comments, None or a string

	def logSettings(self):
		self.logger.debug(self.__str__())

	def gui2Settings(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the dialog GUI to the Settings instance.
		"""
		# self.input = dialog.input()
		pass

	def settings2Gui(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the Settings instance to the dialog GUI.
		"""
		# dialog.setInput(self.input)
		pass

	def __str__(self):
		return(super(Settings, self).__str__() + "\n" +
			"settings.TArg = %s\n" % self.TArg +
			"settings.NArg = %s\n" % self.NArg +
			"settings.PArg = %s\n" % '***' +
			"settings.QArg = %s\n" % self.QArg +
			"settings.FArg = %s\n" % self.FArg +
			"settings.dbFilename = %s\n" % self.dbFilename +
			"QtCore.QSettings = %s\n" % self.qsettings.value(u"database/filename") +
			"settings.AArg = %s\n" % self.AArg +
			"settings.CArg = %s\n" % self.CArg +
			"settings.SArg = %s\n" % self.SArg +
			"settings.OArg = %s\n" % self.OArg +
			"settings.BArg = %s\n" % self.BArg +
			"settings.EArg = %s\n" % self.UArg +
			"settings.XArg = %s\n" % self.XArg +
			"settings.DArg = %s\n" % self.DArg +
			"settings.RArg = %s\n" % self.RArg +
			"settings.UArg = %s\n" % self.EArg +
			"settings.YArg = %s\n" % self.YArg +
			"settings.ZArg = %s\n" % self.ZArg +
			"settings.WArg = %s\n" % self.WArg +
			"settings.MArg = %s\n" % self.MArg +
			"settings.GArg = %s\n" % self.GArg +
			"settings.KArg = %s\n" % self.KArg +
			"settings.n0Arg = %s\n" % self.n0Arg +
			"settings.n1Arg = %s\n" % self.n1Arg +
			"settings.n2Arg = %s\n" % self.n2Arg +
			"settings.n3Arg = %s" % self.n3Arg)

	def store(self):
		self.qsettings.setValue(u"database/filename", self.dbFilename)

	def passphrase(self):
		return self.PArg


class Args(BaseArgs):
	"""
	CLI Argument handling
	"""

	def __init__(self, settings, logger=None):
		"""
		Get all necessary parameters upfront, so the user
		does not have to provide them later on each call.

		@param settings: place to store settings
		@type settings: L{Settings}
		@param logger: holds logger for where to log info/warnings/errors
			if no logger is given it uses the default logger of settings.
			So, usually this would be None.
		@type logger: L{logging.Logger}
		"""
		super(Args, self).__init__(settings, logger)

	def printVersion(self):
		super(Args, self).printVersion()
		print("About " + basics.NAME + ": " + basics.NAME + " is a safe "
			"Password Manager application \nfor people owning a Trezor who prefer "
			"to keep their passwords local \nand not in the cloud. All passwords"
			"are stored locally in a single file.")

	def printUsage(self):
		print('''TrezorPass.py [-v] [-h] [-l <level>] [-p <passphrase>]
			[[-q] -f <pwdbfile>] [-t] [-n]
			[	[-a -g <group> [-k <key> [[-w <password>] [-m <comments>]]]] |
				[-c -g <group> -k <key>] | [-s -g <group> [-k <key>]] |
				[-o -g <group> [-k <key>]] | [-b -g <group> [-k <key>]] |
				[-e [-g <group>]] | [-x] | [-d -g <group> [-k <key>]] ] |
				[-r -g <oldgroupname> -0 <newgroupname>] |
				[-u -g <group> -k <key> [-1 <newkey>] [-2 <newpassword>] [-3 <newcomments>]] |
				[-y <csvfile>] | [-z <csvfile>]	]

		-v, --version
				print the version number
		-h, --help
				print short help text
		-l, --logging
				set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		-p, --passphrase
				provide master passphrase used for Trezor.
				It is recommended that you do not use this command line option
				but rather give the passphrase through a small window interaction.
		-f, --pwdbfile
				name of an existing password file to use instead of the default one;
				must be a valid TrezorPass password file
		-q, --setdefault
				set the file provided with `-f` as default, i.e. this will
				be the password file opened from now on
		-t, --terminal
				run in terminal mode. This mode avoids the GUI.
				`-a`, `-c`, `s`, `-o`, `-b`, `-e`, `-x`, `-d`, `-r`, `-u`,
				`-y`, and `-z` will automatically set `-t` and go into terminal mode.
		-n, --noconfirm
				Eliminates the `Confirm` click on the Trezor button.
				This was only added to facilitate batch testing.
				It should be used EXCLUSIVELY for testing purposes.
				Do NOT use this option with real passwords!
				Furthermore, files encryped with `-n` cannot be decrypted
				without `-n`.

		Operations:
		-a, -add
				add a group and/or a key with or without a password and comments
				Appends new key if key already exists.
		-c, --clip
				copy password of a given group and key to clipboard
				so it can be pasted thereafter
		-s, --show
				print password of a given group and key.
				If no key is given it will print all passwords of the group.
		-o, --showcomments
				print comments of a given group and key.
				If no key is given it will print all comments of the group.
		-b, --showboth
				print passwords and comments of a given group.
				If no key is given it will print all passwords and comments of the group.
		-e, --showkeys
				print keys of a given group.
				If no group is given it will print all keys of the database.
				This prints the hierarchy of the database.
		-x, --showgroups
				print all group names
		-d, --delete
				delete entries of a given group and key.
				If no key is given it will delete the whole group.
		-r, --renamegroup
				rename a group
		-u, --updateentry
				update a key-password-comments entry with new values
		-y, --exportcvs
				export the password database to a CVS file
				The CSV file will be overwriten if it exists already.
		-z, --importcvs
				import a CVS file into the password database

		Additional arguments for operations:
		-g, --group
				to specify the group name
		-k, --key
				to specify the key name
		-w, --password
				to specify the password
		-m, --comments
				to specify the comments
		-0, --newgroupname
				to specify new group name
		-1, --newkeyname
				to specify new key name
		-2, --newpassword
				to specify new password
		-3, --newcomments
				to specify new comments

		All arguments are optional. Usually none needs to be used.

		TrezorPass is based on the following design principles, concepts
		and terminology: The world of passwords and secrets is structured
		in this hierarchy:
		* groups (unlimited)
			+ entries (unlimited entries per group)
				- key		(one per entry)
				- password	(one per entry)
				- comments	(one per entry)
		A `Group` just has a name. The `key` is like an id of the entry.
		The `password` is the secret information, and the `comments` are
		additional secret comments.
		Example groups could be: "Google", "Github", "Bank Abc", "Gym locker",
			"Bike lock", "GPG key"
		The "Google" group could have these example entries: (key, password, comments)
			"account name", "john.doe", ""
			"password", "johnssecretpassword", "last changed in Jan 2017"
			"email address", "john.doe@gmail.com", "johndoe@gmail.com also works"
			"recovery email", "janedoe@gmail.com", "set up in 2016"
		The "Bank Abc" group could have these example entries:
			"user name", "johndoe123", ""
			"password", "ilikepizza", ""
			"PIN", "1234", "used for wires"
			"contact", "Susi", "works in customer care"
			"phone", "123-456-7890", "hot-line, 24x7"
			"URL", "https://bankabc.com/login.php"
		The "Gym locker" group could have these example entries:
			"locker number", "12", "its the third in the second row"
			"code", "4321", ""

		Examples:
		# normal operation
		TrezorPass.py

		# normal operation with verbose logging at Debug level
		TrezorPass.py -l 1

		# open some old backup password database (once)
		TrezorPass.py -f trezorpass.backup.170101.pwdb

		# from now on always by default open password database from environment 2
		TrezorPass.py -q -f trezorpass.env2.pwdb

		# copy password of Google account to clipboard without using GUI
		TrezorPass.py -c -g Google -k password

		# add entry to database without using GUI
		# add secret number 1234 of bike lock
		TrezorPass.py -a -g "Bike lock" -k Number -w 1234 -m "old red number combination lock"

		# update secret number of bike lock to 9876
		TrezorPass.py -a -u "Bike lock" -k Number -2 1234

		# delete secret number entry of bike lock
		TrezorPass.py -a -d "Bike lock" -k Number

		# delete everything about the bike lock group
		TrezorPass.py -a -d "Bike lock"

		# show the gym locker code without GUI
		TrezorPass.py -s -g "Gym locker" -k code

		# show all group names and key names without GUI
		TrezorPass.py --showkeys
		''')

	def parseArgs(self, argv, settings=None, logger=None):
		"""
		Parse the command line arguments and store the results in `settings`.
		Report errors to `logger`.

		@param settings: place to store settings;
			if None the default settings from the Args class will be used.
			So, usually this argument would be None.
		@type settings: L{Settings}
		@param logger: holds logger for where to log info/warnings/errors
			if None the default logger from the Args class will be used.
			So, usually this argument would be None.
		@type logger: L{logging.Logger}
		"""
		# do not call super class parseArgs as partial parsing does not work
		# superclass parseArgs is only useful if there are just -v -h -l [level]
		# get defaults
		if logger is None:
			logger = self.logger
		if settings is None:
			settings = self.settings
		try:
			opts, args = getopt.getopt(argv, "vhl:p:qf:tnacsobexdruy:z:g:k:w:m:0:1:2:3:",
				["version", "help", "logging=", "passphrase=", "setdefault",
				"pwdbfile=", "terminal", "noconfirm", "add", "clip", "show",
				"showcomment", "showboth", "showkeys", "showgroups",
				"delete", "renamegroup", "updateentry", "exportcsv=", "importcsv=",
				"group=", "key=", "password=",
				"comments=", "newgroupname=", "newkeyname=", "newpassword=",
				"newcomments="])
		except getopt.GetoptError as e:
			logger.critical(u'Wrong arguments. Error: %s.', e)
			try:
				msgBox = QMessageBox(QMessageBox.Critical, u"Wrong arguments",
					u"Error: %s" % e)
				msgBox.exec_()
			except Exception:
				pass
			sys.exit(2)
		loglevelused = False
		for opt, arg in opts:
			arg = encoding.normalize_nfc(arg)
			if opt in ("-h", "--help"):
				self.printUsage()
				sys.exit()
			elif opt in ("-v", "--version"):
				self.printVersion()
				sys.exit()
			elif opt in ("-l", "--logging"):
				loglevelarg = arg
				loglevelused = True
			elif opt in ("-t", "--terminal"):
				settings.TArg = True
			elif opt in ("-n", "--noconfirm"):
				settings.NArg = True
			elif opt in ("-p", "--passphrase"):
				settings.PArg = arg
			elif opt in ("-q", "--setdefault"):
				settings.QArg = True
			elif opt in ("-f", "--pwdbfile"):
				settings.FArg = arg
			elif opt in ("-a", "--add"):
				settings.AArg = True
			elif opt in ("-c", "--clip"):
				settings.CArg = True
			elif opt in ("-s", "--show"):
				settings.SArg = True
			elif opt in ("-o", "--showcomments"):
				settings.OArg = True
			elif opt in ("-b", "--showboth"):
				settings.BArg = True
			elif opt in ("-e", "--showkeys"):
				settings.EArg = True
			elif opt in ("-x", "--showgroups"):
				settings.XArg = True
			elif opt in ("-d", "--delete"):
				settings.DArg = True
			elif opt in ("-r", "--renamegroup"):
				settings.RArg = True
			elif opt in ("-u", "--updateentry"):
				settings.UArg = True
			elif opt in ("-y", "--exportcsv"):
				settings.YArg = arg
			elif opt in ("-z", "--importcsv"):
				settings.ZArg = arg
			elif opt in ("-g", "--group"):
				settings.GArg = arg
			elif opt in ("-k", "--key"):
				settings.KArg = arg
			elif opt in ("-w", "--password"):
				settings.WArg = arg
			elif opt in ("-m", "--comments"):
				settings.MArg = arg
			elif opt in ("-0", "--newgroupname"):
				settings.n0Arg = arg
			elif opt in ("-1", "--newkeyname"):
				settings.n1Arg = arg
			elif opt in ("-2", "--newpassword"):
				settings.n2Arg = arg
			elif opt in ("-3", "--newcomments"):
				settings.n3Arg = arg

		if loglevelused:
			try:
				loglevel = int(loglevelarg)
			except Exception as e:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", settings.TArg, logger)
				sys.exit(18)
			if loglevel > 5 or loglevel < 1:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", settings.TArg, logger)
				sys.exit(19)
			settings.LArg = loglevel * 10  # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(settings.LArg)

		# for arg in args:
		# 	# convert all input as possible to unicode UTF-8 NFC
		# 	settings.inputArgs.append(encoding.normalize_nfc(arg))
		# if len(args) >= 1:
		# 	settings.input = args[0]
		if len(args) != 0:
			self.settings.mlogger.log("Incorrect arguments %s found in command line. "
				"Correct your input." % (args), logging.ERROR,
				"Wrong arguments", True, logger)
			sys.exit(20)

		if ((settings.FArg == u"") or (settings.FArg is None)) and settings.QArg:
			self.settings.mlogger.log("Don't use `-q` without the `-f` argument "
				"or with an empty filename. Aborting.",
				logging.ERROR, "Wrong arguments", True, logger)
			sys.exit(21)

		if settings.FArg is not None:
			if settings.FArg != '':
				if not os.path.isfile(settings.FArg):
					self.settings.mlogger.log("File \"%s\" does not exist, is not a proper file, "
						"or is a directory. Aborting." % (settings.FArg), logging.ERROR,
						"File IO Error", True, logger)
					sys.exit(21)
				elif not os.access(settings.FArg, os.R_OK):
					self.settings.mlogger.log("File \"%s\" cannot be read. No read permissions. "
						"Aborting." % (settings.FArg), logging.ERROR, "File IO Error",
						True, logger)
					sys.exit(22)
				else:
					settings.dbFilename = settings.FArg
					if settings.QArg:
						settings.store()  # update/store permanently
			else:  # FArg == ''
				settings.dbFilename = None  # force it call initialize

		ii = 0
		for ff in [settings.AArg, settings.CArg, settings.SArg, settings.OArg,
			settings.BArg, settings.EArg, settings.XArg, settings.DArg,
			settings.RArg, settings.UArg]:
			if ff:
				ii += 1
		for ff in [settings.YArg, settings.ZArg]:
			if ff is not None:
				ii += 1
		if ii > 1:
			self.settings.mlogger.log("Only one of `-a`, `-c`, `-s`, `-o`, "
				"`-b`, `-e`, `-x`, `-d`, `-r`, `-u`, `-y`, and `-z` can be used. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(23)
		if ii == 1:
			settings.TArg = True

		if settings.AArg and settings.GArg is None:
			self.settings.mlogger.log("If `-a` is chosen, then `-g` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(24)

		if settings.AArg and settings.WArg is not None and settings.KArg is None:
			self.settings.mlogger.log("If `-a` and `-w` are chosen, then `-k` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(25)

		if settings.AArg and settings.MArg is not None and settings.KArg is None:
			self.settings.mlogger.log("If `-a` and `-m` are chosen, then `-k` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(25)

		if settings.CArg and (settings.GArg is None or settings.KArg is None):
			self.settings.mlogger.log("If `-c` is chosen, then `-g` and `-k` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(26)

		if settings.CArg and (settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-c` is chosen, then neither `-w` nor `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(27)

		if settings.SArg and settings.GArg is None:
			self.settings.mlogger.log("If `-s` is chosen, then `-g` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(28)

		if settings.SArg and (settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-s` is chosen, then neither `-w` nor `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(29)

		if settings.OArg and settings.GArg is None:
			self.settings.mlogger.log("If `-o` is chosen, then `-g` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(30)

		if settings.OArg and (settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-o` is chosen, then neither `-w` nor `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(31)

		if settings.BArg and settings.GArg is None:
			self.settings.mlogger.log("If `-b` is chosen, then `-g` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(32)

		if settings.BArg and (settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-b` is chosen, then neither `-w` nor `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(33)

		if settings.EArg and (settings.KArg is not None or settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-e` is chosen, then none of `-k`, `-w` or `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(34)

		if settings.XArg and (settings.GArg is not None or settings.KArg is not None or settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-x` is chosen, then none of `-g`, `-k`, `-w` or `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(35)

		if settings.DArg and settings.GArg is None:
			self.settings.mlogger.log("If `-d` is chosen, then `-g` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(36)

		if settings.DArg and (settings.WArg is not None or settings.MArg is not None):
			self.settings.mlogger.log("If `-d` is chosen, then neither `-w` nor `-m` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(37)

		if (settings.AArg or settings.CArg or settings.SArg or settings.OArg or
			settings.BArg or settings.EArg or settings.XArg or settings.DArg or
			settings.YArg is not None or settings.ZArg is not None) and (
			settings.n0Arg is not None or settings.n1Arg is not None or
			settings.n2Arg is not None or settings.n3Arg is not None):
			self.settings.mlogger.log("If `-a`, `-c`, `-s`, `-o`, `-b`, `-e`, "
				"`-x`, `-d`, `y`, or `-z` is chosen, then none of `-0`, `-1`, `-2` or `-3` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(38)

		if settings.RArg and (settings.KArg is not None or settings.WArg is not None or
			settings.MArg is not None or settings.n1Arg is not None or
			settings.n2Arg is not None or settings.n3Arg is not None):
			self.settings.mlogger.log("If `-r` is chosen, then none of "
				"`-k`, `-w` or `-m`, `-1`, `-2` or `-3` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(39)

		if settings.RArg and (settings.GArg is None or settings.n0Arg is None):
			self.settings.mlogger.log("If `-r` is chosen, "
				"then both `-g` and `-0` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(40)

		if settings.UArg and (settings.WArg is not None or
			settings.MArg is not None or settings.n0Arg is not None):
			self.settings.mlogger.log("If `-u` is chosen, then none of "
				"`-w`, `-m`, or `-0` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(41)

		if settings.UArg and (settings.GArg is None or settings.KArg is None):
			self.settings.mlogger.log("If `-u` is chosen, "
				"then both of `-g` and `-k` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(42)

		if settings.UArg and (settings.n1Arg is None and
			settings.n2Arg is None and settings.n3Arg is None):
			self.settings.mlogger.log("If `-u` is chosen, "
				"then at least one must be but possibly multiple of `-1`, `-2` and `-3` "
				"can be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(43)

		if settings.YArg is not None and (settings.GArg is not None or
			settings.KArg is not None or settings.WArg is not None or
			settings.MArg is not None or settings.n0Arg is not None):
			self.settings.mlogger.log("If `-y` is chosen, then none of "
				"`-g`, `-k`, `-w`, `-m`, or `-0` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(44)

		if settings.ZArg is not None and (settings.GArg is not None or
			settings.KArg is not None or settings.WArg is not None or
			settings.MArg is not None or settings.n0Arg is not None):
			self.settings.mlogger.log("If `-z` is chosen, then none of "
				"`-g`, `-k`, `-w`, `-m`, or `-0` must be provided. "
				"Aborting.", logging.ERROR, "Wrong arguments",
				True, logger)
			sys.exit(45)

		settings.mlogger.setTerminalMode(settings.TArg)
		self.settings.mlogger.log(u"%s Version: %s (%s)" %
			(basics.NAME, basics.VERSION_STR, basics.VERSION_DATE_STR),
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"Python: %s" % sys.version.replace(" \n", "; "),
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"Qt Version: %s" % QT_VERSION_STR,
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"PyQt Version: %s" % PYQT_VERSION_STR,
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u'Logging level set to %s (%d).' %
			(logging.getLevelName(settings.LArg), settings.LArg),
			logging.INFO, "Logging", True, logger)
		self.settings.mlogger.log(settings,
			logging.DEBUG, "Settings", True, logger)
		if settings.NArg:
			self.settings.mlogger.log(u'Warning: the `--noconfirm` option is set. '
				'This should only be set for batch testing. Do not use this '
				'mode with real passwords.',
				logging.WARNING, "Settings", True, logger)

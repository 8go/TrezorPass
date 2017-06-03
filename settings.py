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
		self.dbFilename = None
		self.qsettings = QSettings(u"ConstructibleUniverse", u"TrezorPass")
		fname = self.qsettings.value(u"database/filename")
		# returns None or unicode string
		if fname is not None:
			self.dbFilename = encoding.normalize_nfc(fname)
		self.TArg = False
		self.PArg = None
		self.DArg = False
		self.FArg = u""

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
			"settings.PArg = %s\n" % u'***' +
			"settings.DArg = %s\n" % self.DArg +
			"settings.FArg = %s\n" % self.FArg +
			"settings.dbFilename = %s\n" % self.dbFilename +
			"QtCore.QSettings = %s" % self.qsettings.value(u"database/filename"))

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
		print('''TrezorPass.py [-v] [-h] [-l <level>] [-p <passphrase>] [[-d] -f <pwdbfile>]
		-v, --version
				print the version number
		-h, --help
				print short help text
		-l, --logging
				set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		-p, --passphrase
				master passphrase used for Trezor.
				It is recommended that you do not use this command line option
				but rather give the passphrase through a small window interaction.
		-f, --pwdbfile
				name of an existing password file to use instead of the default one;
				must be a valid TrezorPass password file
		-d, --setdefault
				set the file provided with `-f` as default, i.e. this will
				be the password file opened from now on

		All arguments are optional. Usually none needs to be used.

		Examples:
		# normal operation
		TrezorPass.py

		# normal operation with verbose logging at Debug level
		TrezorPass.py -l 1

		# open some old backup password database (once)
		TrezorPass.py -f trezorpass.backup.170101.pwdb

		# from now on always by default open password database from environment 2
		TrezorPass.py -d -f trezorpass.env2.pwdb
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
			opts, args = getopt.getopt(argv, "vhl:p:df:",
				["version", "help", "logging=", "passphrase=", "setdefault", "pwdbfile="])
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
			elif opt in ("-p", "--passphrase"):
				settings.PArg = arg
			elif opt in ("-d", "--setdefault"):
				settings.DArg = True
			elif opt in ("-f", "--pwdbfile"):
				settings.FArg = arg

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

		if (settings.FArg == "") and settings.DArg:
			self.settings.mlogger.log("Don't used `-d` without the `-f` argument. Aborting.",
				logging.ERROR, "Wrong arguments", True, logger)
			sys.exit(21)

		if (settings.FArg != "") and not os.path.isfile(settings.FArg):
			self.settings.mlogger.log("File \"%s\" does not exist, is not a proper file, "
				"or is a directory. Aborting." % (settings.FArg), logging.ERROR,
				"File IO Error", True, logger)
			sys.exit(21)
		elif (settings.FArg != "") and not os.access(settings.FArg, os.R_OK):
			self.settings.mlogger.log("File \"%s\" cannot be read. No read permissions. "
				"Aborting." % (settings.FArg), logging.ERROR, "File IO Error",
				True, logger)
			sys.exit(22)
		elif settings.FArg != u"":
			settings.dbFilename = settings.FArg
			if settings.DArg:
				settings.store()  # update/store permanently

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

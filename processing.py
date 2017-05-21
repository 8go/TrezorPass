import sys
import struct
import logging
import getopt
import re
import datetime
import traceback
import os.path

from PyQt4 import QtCore
from PyQt4 import QtGui


from trezorlib.client import CallException, PinException

from encoding import q2s, s2q
import basics

class Settings(object):
	"""
	Settings for command line options
	Settings for password database location
	"""

	def __init__(self, logger):
		self.dbFilename = None
		self.settings = QtCore.QSettings("ConstructibleUniverse", "TrezorPass")
		fname = self.settings.value("database/filename")
		if fname.isValid():
			self.dbFilename = q2s(fname.toString())

		self.logger = logger
		self.VArg = False
		self.HArg = False
		self.PArg = None
		self.DArg = False
		self.FArg = ""

	def printSettings(self):
		self.logger.debug("self.dbFilename = %s", self.dbFilename)
		fname = self.settings.value("database/filename")
		self.logger.debug("QtCore.QSettings = %s", q2s(fname.toString()))
		self.logger.debug("self.VArg = %s", self.VArg)
		self.logger.debug("self.HArg = %s", self.HArg)
		self.logger.debug("self.PArg = %s", self.PArg)
		self.logger.debug("self.DArg = %s", self.DArg)
		self.logger.debug("self.FArg = %s", self.FArg)

	def store(self):
		self.settings.setValue("database/filename", s2q(self.dbFilename))

	def passphrase(self):
		return self.PArg


def usage():
	print """TrezorPass.py [-v] [-h] [-l <level>] [-p <passphrase>] [[-d] -f <pwdbfile>]
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
		"""

def printVersion():
	"""
	Show about and version information.
	"""
	print "Version: %s from %s" % (basics.TREZORPASSSOFTWAREVERSION, basics.TREZORPASSSOFTWAREVERSIONTEXT)
	print("About TrezorPass: TrezorPass is a safe Password Manager application \n"
		"for people owning a Trezor who prefer to keep their passwords local \n"
		"and not on the cloud. All passwords are stored locally in a single file.")

def parseArgs(argv, settings, logger):
	try:
		opts, args = getopt.getopt(argv,"vhl:p:df:",
			["version","help","logging=","passphrase=","setdefault","pwdbfile="])
	except getopt.GetoptError, e:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: " + str(e))
		msgBox.exec_()
		logger.critical('Wrong arguments. Error: %s.', str(e))
		sys.exit(2)
	loglevelused = False
	for opt, arg in opts:
		if opt in ("-h","--help"):
			usage()
			sys.exit()
		elif opt in ("-v", "--version"):
			printVersion()
			sys.exit()
		elif opt in ("-l", "--logging"):
			loglevelarg = arg
			loglevelused = True
		elif opt in ("-p", "--passphrase"):
			settings.PArg = arg
		elif opt in ("-d", "--setdefault"):
			settings.DArg = True
		elif opt in ("-f", "--pwdbfile"):
			settings.FArg = arg

	if loglevelused:
		try:
			loglevel = int(loglevelarg)
		except Exception, e:
			reportLogging("Logging level not specified correctly. "
				"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
				"Wrong arguments", settings, logger)
			sys.exit(18)
		if loglevel > 5 or loglevel < 1:
			reportLogging("Logging level not specified correctly. "
				"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
				"Wrong arguments", settings, logger)
			sys.exit(19)
		basics.LOGGINGLEVEL = loglevel * 10 # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(basics.LOGGINGLEVEL)
		logger.info('Logging level set to %s (%d).',
			logging.getLevelName(basics.LOGGINGLEVEL), basics.LOGGINGLEVEL)

	if len(args) != 0:
		reportLogging("Incorrect arguments %s found in command line. "
			"Correct your input." % str(args), logging.ERROR,
			"Wrong arguments", settings, logger)
		sys.exit(20)

	if (settings.FArg == "") and settings.DArg:
		reportLogging("Don't used `-d` without the `-f` argument. Aborting.",
			logging.ERROR,
			"Wrong arguments", settings, logger)
		sys.exit(21)

	if (settings.FArg != "") and not os.path.isfile(settings.FArg):
		reportLogging("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Aborting." % settings.FArg, logging.ERROR,
			"File IO Error", settings, logger)
		sys.exit(21)
	elif (settings.FArg != "") and not os.access(settings.FArg, os.R_OK):
		reportLogging("File \"%s\" cannot be read. No read permissions. "
			"Aborting." % settings.FArg, logging.ERROR, "File IO Error",
			settings, logger)
		sys.exit(22)
	elif settings.FArg != "":
		settings.dbFilename = settings.FArg
		if settings.DArg:
			settings.store() # update/store permanently
	settings.printSettings()

def reportLogging(str, level, title, settings, logger):
	"""
	Displays string str depending on scenario:
	a) on terminal mode: thru logger (except if loglevel == NOTSET)
	b) thru QMessageBox()

	NOTSET means it will be printed, both terminal and QMessageBox

	@param str: string to report/log
	@param level: log level from DEBUG to CRITICAL
	@param title: window title text
	"""
	if level == logging.NOTSET:
		print str # stdout
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information,
			title, "%s" % (str))
		msgBox.exec_()
	elif level == logging.DEBUG:
		logger.debug(str)
		# don't spam the user with too many pop-ups
		# For debug, instead of a pop-up we write to stdout
		# do nthing
	elif level == logging.INFO:
		logger.info(str)
		if logger.getEffectiveLevel() <= level:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information,
				title, "Info: %s" % (str))
			msgBox.exec_()
	elif level == logging.WARN:
		logger.warning(str)
		if logger.getEffectiveLevel() <= level:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Warning,
				title, "Warning: %s" % (str))
			msgBox.exec_()
	elif level == logging.ERROR:
		logger.error(str)
		if logger.getEffectiveLevel() <= level:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
				title, "Error: %s" % (str))
			msgBox.exec_()
	elif level == logging.CRITICAL:
		logger.critical(str)
		if logger.getEffectiveLevel() <= level:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
				title, "Critical: %s" % (str))
			msgBox.exec_()

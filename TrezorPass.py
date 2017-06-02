#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import os.path
import csv
import time
from Crypto import Random
from shutil import copyfile

from PyQt5.QtWidgets import QApplication  # for the clipboard and window

from dialogs import MainWindow

import basics
import utils
import settings
import encoding
import processing
import trezor_app_generic
import password_map
from backup import Backup

"""
The file with the main function.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


def showGui(trezor, app, dialog, settings):
	"""
	Start the main window.
	Stay in the main window until the user quits.

	Makes sure a session is created on Trezor.

	@param trezor: Trezor client
	@param dialog: the GUI window
	@param settings: Settings object to store input and output
		also holds any necessary settings
	"""
	settings.settings2Gui(dialog)
	dialog.show()
	if not app.exec_():
		# Esc or exception or Quit/Close/Done
		settings.mlogger.log("Shutting down due to user request "
			"(Done/Quit was called).", logging.DEBUG, "GUI IO")
		# sys.exit(4)
	settings.gui2Settings(dialog)


def useTerminal(pwMap, settings):
	"""
	Currently there are no terminal-only functins or a
	Terminal-mode, but one could envision one in the future
	with commands like:
		-t --rm groupName [key]
		-t --mv groupNameOld groupNameNew
		-t --add groupName [key password comments]
	"""
	settings.mlogger.log(u"Entering Terminal mode. GUI wil not be called.",
		logging.DEBUG, u"Arguments")


def main():
	# Terminal-mode is not yet implemented, set it to True once it is
	terminalModeImplemented = False
	app = QApplication(sys.argv)
	sets = settings.Settings()  # initialize settings
	# parse command line
	args = settings.Args(sets)
	args.parseArgs(sys.argv[1:])

	trezor = trezor_app_generic.setupTrezor(sets.TArg, sets.mlogger)
	# trezor.clear_session() ## not needed
	trezor.prefillReadpinfromstdin(sets.TArg)
	trezor.prefillReadpassphrasefromstdin(sets.TArg)
	trezor.prefillPassphrase(sets.passphrase())
	trezor.prefillPassphrase(u'trezorpass')###sremove this line'!!! zzzz

	pwMap = password_map.PasswordMap(trezor, sets)

	if sets.TArg and terminalModeImplemented:
		sets.mlogger.log(u"Terminal mode --terminal was set. Avoiding GUI.",
			logging.INFO, u"Arguments")
	else:
		# our GUI does not have a status textBrowser Widget
		# we do not log to the GUI
		sets.mlogger.setQtextbrowser(None)
		dialog = MainWindow(None, sets, sets.dbFilename)
		# sets.mlogger.setQtextheader(dialog.descrHeader())
		# sets.mlogger.setQtextcontent(dialog.descrContent())
		# sets.mlogger.setQtexttrailer(dialog.descrTrailer())

	sets.mlogger.log("Trezor label: %s" % trezor.features.label,
		logging.DEBUG, "Trezor IO")
	sets.mlogger.log("Click 'Confirm' on Trezor to give permission "
		"whenever required.", logging.DEBUG, "Trezor IO")

	if sets.dbFilename and os.path.isfile(sets.dbFilename):
		pwMap.loadWithChecks(sets.dbFilename)

		if pwMap.version == 1:
			copyfile(sets.dbFilename, sets.dbFilename + ".v1.backup")
			sets.mloggeer.log("Updating Trezorpass database file from "
				"version 1 to version 2. Please make a backup of \"%s\" now!" %
				(sets.dbFilename), logging.NOTSET,
				"Trezor datbase")
			processing.updatePwMapFromV1ToV2(pwMap, sets)
	else:
		processing.initializeStorage(trezor, pwMap, sets)

	if sets.TArg and terminalModeImplemented:
		useTerminal(pwMap, sets)
	else:
		# user wants GUI, so we call the GUI
		dialog.setPwMap(pwMap)
		showGui(trezor, app, dialog, sets)
	# cleanup
	sets.mlogger.log("Cleaning up before shutting down.", logging.DEBUG, "Info")
	trezor.close()


if __name__ == '__main__':
	main()

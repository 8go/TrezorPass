#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import os.path
from shutil import copyfile
import traceback

from PyQt5.QtWidgets import QApplication  # for the clipboard and window

from dialogs import MainWindow

import settings
import processing
import trezor_app_generic
import password_map
import sys
import codecs

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
	"""
	settings.mlogger.log(u"Entering Terminal mode. GUI will not be called.",
		logging.DEBUG, u"Arguments")
	try:
		if settings.BArg:
			pwMap.showBoth(settings.GArg, settings.KArg)
		if settings.CArg:
			pwMap.clipPassword(settings.GArg, settings.KArg)
		if settings.SArg:
			pwMap.showPassword(settings.GArg, settings.KArg)
		if settings.OArg:
			pwMap.showComments(settings.GArg, settings.KArg)
		if settings.DArg:
			pwMap.deletePasswordEntry(settings.GArg, settings.KArg, askUser=True)
			pwMap.save(settings.dbFilename)
		if settings.EArg:
			pwMap.showKeys(settings.GArg)
		if settings.XArg:
			pwMap.showGroupNames()
		if settings.AArg:
			pwMap.addEntry(settings.GArg, settings.KArg, settings.WArg, settings.MArg)
			pwMap.save(settings.dbFilename)
		if settings.RArg:
			pwMap.renameGroup(settings.GArg, settings.n0Arg, moreSecure=True)
			pwMap.save(settings.dbFilename)
		if settings.UArg:
			pwMap.updateEntryInGroup(settings.GArg, settings.KArg,
				settings.n1Arg, settings.n2Arg, settings.n3Arg, askUser=True)
			pwMap.save(settings.dbFilename)
		if settings.YArg:
			pwMap.exportCsv(settings.YArg)
		if settings.ZArg:
			pwMap.importCsv(settings.ZArg)
			pwMap.save(settings.dbFilename)
	except Exception as e:
		settings.mlogger.log("Error/Warning/Info: %s" % (e),
			logging.CRITICAL, u"Arguments")
		if settings.logger.getEffectiveLevel() <= logging.DEBUG:
			traceback.print_exc()  # prints to stderr


def main():
	if sys.version_info[0] < 3:  # Py2-vs-Py3:
		# redirecting output to a file can cause unicode problems
		# read: https://stackoverflow.com/questions/5530708/
		# To fix it either run the scripts as: PYTHONIOENCODING=utf-8 python TrezorPass.py
		# or add the following line of code.
		# Only shows up in python2 TrezorPass.py >> log scenarios
		# Exception: 'ascii' codec can't encode characters in position 10-13: ordinal not in range(128)
		sys.stdout = codecs.getwriter('utf-8')(sys.stdout)

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

	pwMap = password_map.PasswordMap(trezor, sets)

	if sets.TArg:
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

	if sets.TArg:
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

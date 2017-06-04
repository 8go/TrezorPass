from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import logging
import os
import base64
import hashlib
from shutil import copyfile
import csv
import time
import sys

from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QDialogButtonBox
from PyQt5.QtWidgets import QMessageBox, QFileDialog, QLineEdit, QShortcut
from PyQt5.QtWidgets import QAbstractItemView, QTableWidgetItem
from PyQt5.QtWidgets import QMenu, QAction, QHeaderView
from PyQt5.QtGui import QPixmap, QKeySequence, QTextDocument, QStandardItem
from PyQt5.QtGui import QStandardItemModel
from PyQt5.QtCore import QT_VERSION_STR, QTimer, QDir, Qt, QVariant
from PyQt5.QtCore import QSortFilterProxyModel, QItemSelectionModel
from PyQt5.Qt import PYQT_VERSION_STR

from trezorlib.client import CallException

from ui_initialize_dialog import Ui_InitializeDialog
from ui_add_group_dialog import Ui_AddGroupDialog
from ui_add_password_dialog import Ui_AddPasswordDialog
from ui_main_window import Ui_MainWindow

import basics
import encoding

"""
This code should cover the GUI of the business logic of the application.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


class InitializeDialog(QDialog, Ui_InitializeDialog):

	def __init__(self):
		super(InitializeDialog, self).__init__()

		# Set up the user interface from Designer.
		self.setupUi(self)

		# Make some local modifications.
		self.masterEdit1.textChanged.connect(self.validate)
		self.masterEdit2.textChanged.connect(self.validate)
		self.pwFileEdit.textChanged.connect(self.validate)
		self.pwFileButton.clicked.connect(self.selectPwFile)
		self.validate()

	def setPw1(self, pw):
		self.masterEdit1.setText(encoding.normalize_nfc(pw))

	def setPw2(self, pw):
		self.masterEdit2.setText(encoding.normalize_nfc(pw))

	def pw1(self):
		return encoding.normalize_nfc(self.masterEdit1.text())

	def pw2(self):
		return encoding.normalize_nfc(self.masterEdit2.text())

	def pwFile(self):
		return encoding.normalize_nfc(self.pwFileEdit.text())

	def validate(self):
		"""
		Enable OK button only if both master and backup are repeated
		without typo and some password file is selected.
		"""
		same = self.pw1() == self.pw2()
		fileSelected = (self.pwFileEdit.text() != u'')
		button = self.buttonBox.button(QDialogButtonBox.Ok)
		button.setEnabled(same and fileSelected)

	def selectPwFile(self):
		"""
		Show file dialog and return file user chose to store the
		encrypted password database.
		"""
		path = QDir.currentPath()
		dialog = QFileDialog(self, u"Select password database file",
			path, "(*"+basics.PWDB_FILEEXT+")")
		dialog.setAcceptMode(QFileDialog.AcceptSave)

		res = dialog.exec_()
		if not res:
			return

		fname = dialog.selectedFiles()[0]
		self.pwFileEdit.setText(fname)


class AddGroupDialog(QDialog, Ui_AddGroupDialog):

	def __init__(self, groups, settings):
		super(AddGroupDialog, self).__init__()
		self.setupUi(self)
		self.newGroupEdit.textChanged.connect(self.validate)
		self.groups = groups
		self.settings = settings

		# disabled for empty string
		button = self.buttonBox.button(QDialogButtonBox.Ok)
		button.setEnabled(False)

	def newGroupName(self):
		return encoding.normalize_nfc(self.newGroupEdit.text())

	def setNewGroupName(self, text):
		self.newGroupEdit.setText(encoding.normalize_nfc(text))

	def validate(self):
		"""
		Validates input if name is not empty and is different from
		existing group names.
		"""
		valid = True
		text = self.newGroupName()
		if text == u'':
			valid = False

		if text in self.groups:
			self.settings.mlogger.log('Group "%s" already exists. Cannot have '
				'duplicate group names. Try a different name.' % (text),
				logging.DEBUG, "Arguments")
			valid = False

		button = self.buttonBox.button(QDialogButtonBox.Ok)
		button.setEnabled(valid)


class AddPasswordDialog(QDialog, Ui_AddPasswordDialog):

	def __init__(self, trezor, settings):
		super(AddPasswordDialog, self).__init__()
		self.setupUi(self)
		self.pwEdit1.textChanged.connect(self.validatePw)
		self.pwEdit2.textChanged.connect(self.validatePw)
		self.showHideButton.clicked.connect(self.switchPwVisible)
		self.generatePasswordButton.clicked.connect(self.generatePassword)
		self.trezor = trezor
		self.settings = settings

	def key(self):
		return encoding.normalize_nfc(self.keyEdit.text())

	def pw1(self):
		return encoding.normalize_nfc(self.pwEdit1.text())

	def pw2(self):
		return encoding.normalize_nfc(self.pwEdit2.text())

	def comments(self):
		doc = self.commentsEdit.document().toPlainText()
		if doc is None:
			doc = u''
		else:
			doc = encoding.normalize_nfc(doc)
		return doc

	def validatePw(self):
		same = self.pw1() == self.pw2()
		button = self.buttonBox.button(QDialogButtonBox.Ok)
		button.setEnabled(same)

	def switchPwVisible(self):
		pwMode = self.pwEdit1.echoMode()
		if pwMode == QLineEdit.Password:
			newMode = QLineEdit.Normal
		else:
			newMode = QLineEdit.Password

		self.pwEdit1.setEchoMode(newMode)
		self.pwEdit2.setEchoMode(newMode)

	def generatePassword(self):
		trezor_entropy = self.trezor.get_entropy(32)
		urandom_entropy = os.urandom(32)
		passwdBytes = hashlib.sha256(trezor_entropy + urandom_entropy).digest()
		# base85 encoding not yet implemented in Python 2.7, (requires Python 3+)
		# so we use base64 encoding
		# remove the base64 buffer char =, remove easily confused chars 0 and O, as well as I and l
		passwdB64bytes = base64.urlsafe_b64encode(passwdBytes)
		passwdB64bytes.replace(b'=', '')
		passwdB64bytes.replace(b'0', '')
		passwdB64bytes.replace(b'O', '')
		passwdB64bytes.replace(b'I', '')
		passwdB64bytes.replace(b'l', '')
		# print "bin =", passwdBin, ", base =", passwdB64, " binlen =", len(passwdBin), "baselen =", len(passwdB64)
		# instead of setting the values, we concatenate them to the existing values
		# This way, by clicking the "Generate password" button one can create an arbitrary long random password.
		self.pwEdit1.setText(self.pw1() + encoding.normalize_nfc(passwdB64bytes))
		self.pwEdit2.setText(self.pw2() + encoding.normalize_nfc(passwdB64bytes))


class MainWindow(QMainWindow, Ui_MainWindow):
	"""
	Main window for the application with groups and password lists
	"""

	KEY_IDX = 0  # column where key is shown in password table
	PASSWORD_IDX = 1  # column where password is shown in password table
	COMMENTS_IDX = 2  # column where comments is shown in password table
	NO_OF_PASSWDTABLE_COLUMNS = 3  # 3 columns: key + value/passwd/secret + comments
	CACHE_IDX = 0  # column of QWidgetItem in whose data we cache decrypted passwords+comments

	def __init__(self, pwMap, settings, dbFilename):
		"""
		@param pwMap: a PasswordMap instance with encrypted passwords
		@param dbFilename: file name for saving pwMap
		"""
		super(MainWindow, self).__init__()
		self.setupUi(self)

		self.logger = settings.logger
		self.settings = settings
		self.pwMap = pwMap
		self.selectedGroup = None
		self.modified = False  # modified flag for "Save?" question on exit
		self.dbFilename = dbFilename

		self.groupsModel = QStandardItemModel(parent=self)
		self.groupsModel.setHorizontalHeaderLabels([u"Password group"])
		self.groupsFilter = QSortFilterProxyModel(parent=self)
		self.groupsFilter.setSourceModel(self.groupsModel)

		self.groupsTree.setModel(self.groupsFilter)
		self.groupsTree.setContextMenuPolicy(Qt.CustomContextMenu)
		self.groupsTree.customContextMenuRequested.connect(self.showGroupsContextMenu)
		# Dont use e following line, it would cause loadPasswordsBySelection
		# to be called twice on mouse-click.
		# self.groupsTree.clicked.connect(self.loadPasswordsBySelection)
		self.groupsTree.selectionModel().selectionChanged.connect(self.loadPasswordsBySelection)
		self.groupsTree.setSortingEnabled(True)

		self.passwordTable.setContextMenuPolicy(Qt.CustomContextMenu)
		self.passwordTable.customContextMenuRequested.connect(self.showPasswdContextMenu)
		self.passwordTable.setSelectionBehavior(QAbstractItemView.SelectRows)
		self.passwordTable.setSelectionMode(QAbstractItemView.SingleSelection)

		shortcut = QShortcut(QKeySequence(u"Ctrl+C"), self.passwordTable, self.copyPasswordFromSelection)
		shortcut.setContext(Qt.WidgetShortcut)

		self.actionQuit.triggered.connect(self.close)
		self.actionQuit.setShortcut(QKeySequence(u"Ctrl+Q"))
		self.actionExport.triggered.connect(self.exportCsv)
		self.actionImport.triggered.connect(self.importCsv)
		self.actionBackup.triggered.connect(self.saveBackup)
		self.actionAbout.triggered.connect(self.printAbout)
		self.actionSave.triggered.connect(self.saveDatabase)
		self.actionSave.setShortcut(QKeySequence(u"Ctrl+S"))

		# headerKey = QTableWidgetItem(u"Key")
		# headerValue = QTableWidgetItem(u"Password/Value")
		# headerComments = QTableWidgetItem(u"Comments")
		# self.passwordTable.setColumnCount(self.NO_OF_PASSWDTABLE_COLUMNS)
		# self.passwordTable.setHorizontalHeaderItem(self.KEY_IDX, headerKey)
		# self.passwordTable.setHorizontalHeaderItem(self.PASSWORD_IDX, headerValue)
		# self.passwordTable.setHorizontalHeaderItem(self.COMMENTS_IDX, headerComments)
		#
		# self.passwordTable.resizeRowsToContents()
		# self.passwordTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
		# self.passwordTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		# self.passwordTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)

		self.searchEdit.textChanged.connect(self.filterGroups)

		if pwMap is not None:
			self.setPwMap(pwMap)

		self.clipboard = QApplication.clipboard()

		self.timer = QTimer(parent=self)
		self.timer.timeout.connect(self.clearClipboard)

	def setPwMap(self, pwMap):
		""" if not done in __init__ pwMap can be supplied later """
		self.pwMap = pwMap
		groupNames = self.pwMap.groups.keys()
		for groupName in groupNames:
			item = QStandardItem(groupName)
			self.groupsModel.appendRow(item)
		self.groupsTree.sortByColumn(0, Qt.AscendingOrder)
		self.settings.mlogger.log("pwMap was initialized.",
			logging.DEBUG, "GUI IO")

	def setModified(self, modified):
		"""
		Sets the modified flag so that user is notified when exiting
		with unsaved changes.
		"""
		self.modified = modified
		self.setWindowTitle("TrezorPass" + "*" * int(self.modified))

	def showGroupsContextMenu(self, point):
		"""
		Show context menu for group management.

		@param point: point in self.groupsTree where click occured
		"""
		self.addGroupMenu = QMenu(self)
		newGroupAction = QAction('Add group', self)
		editGroupAction = QAction('Edit group', self)
		deleteGroupAction = QAction('Delete group', self)
		self.addGroupMenu.addAction(newGroupAction)
		self.addGroupMenu.addAction(editGroupAction)
		self.addGroupMenu.addAction(deleteGroupAction)

		# disable deleting if no point is clicked on
		proxyIdx = self.groupsTree.indexAt(point)
		itemIdx = self.groupsFilter.mapToSource(proxyIdx)
		item = self.groupsModel.itemFromIndex(itemIdx)
		if item is None:
			deleteGroupAction.setEnabled(False)

		action = self.addGroupMenu.exec_(self.groupsTree.mapToGlobal(point))

		if action == newGroupAction:
			self.createGroupWithCheck()
		elif action == editGroupAction:
			self.editGroupWithCheck(item)
		elif action == deleteGroupAction:
			self.deleteGroupWithCheck(item)

	def showPasswdContextMenu(self, point):
		"""
		Show context menu for password management

		@param point: point in self.passwordTable where click occured
		"""
		self.passwdMenu = QMenu(self)
		showPasswordAction = QAction('Show password', self)
		copyPasswordAction = QAction('Copy password', self)
		copyPasswordAction.setShortcut(QKeySequence("Ctrl+C"))
		showCommentsAction = QAction('Show comments', self)
		copyCommentsAction = QAction('Copy comments', self)
		newItemAction = QAction('New item', self)
		deleteItemAction = QAction('Delete item', self)
		editItemAction = QAction('Edit item', self)
		self.passwdMenu.addAction(showPasswordAction)
		self.passwdMenu.addAction(copyPasswordAction)
		self.passwdMenu.addSeparator()
		self.passwdMenu.addAction(showCommentsAction)
		self.passwdMenu.addAction(copyCommentsAction)
		self.passwdMenu.addSeparator()
		self.passwdMenu.addAction(newItemAction)
		self.passwdMenu.addAction(deleteItemAction)
		self.passwdMenu.addAction(editItemAction)

		# disable creating if no group is selected
		if self.selectedGroup is None:
			newItemAction.setEnabled(False)

		# disable deleting if no point is clicked on
		item = self.passwordTable.itemAt(point.x(), point.y())
		if item is None:
			deleteItemAction.setEnabled(False)
			showPasswordAction.setEnabled(False)
			copyPasswordAction.setEnabled(False)
			showCommentsAction.setEnabled(False)
			copyCommentsAction.setEnabled(False)
			editItemAction.setEnabled(False)

		action = self.passwdMenu.exec_(self.passwordTable.mapToGlobal(point))
		if action == newItemAction:
			self.createPassword()
		elif action == deleteItemAction:
			self.deletePassword(item)
		elif action == editItemAction:
			self.editPassword(item)
		elif action == copyPasswordAction:
			self.copyPasswordFromItem(item)
		elif action == showPasswordAction:
			self.showPassword(item)
		elif action == copyCommentsAction:
			self.copyCommentsFromItem(item)
		elif action == showCommentsAction:
			self.showComments(item)

	def createGroup(self, groupName, group=None):
		"""
		Slot to create a password group.
		"""
		newItem = QStandardItem(groupName)
		self.groupsModel.appendRow(newItem)
		self.pwMap.addGroup(groupName)
		if group is not None:
			self.pwMap.replaceGroup(groupName, group)

		# make new item selected to save a few clicks
		itemIdx = self.groupsModel.indexFromItem(newItem)
		proxyIdx = self.groupsFilter.mapFromSource(itemIdx)
		self.groupsTree.selectionModel().select(proxyIdx,
			QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
		self.groupsTree.sortByColumn(0, Qt.AscendingOrder)

		# Make item's passwords loaded so new key-value entries can be created
		# right away - better from UX perspective.
		self.loadPasswords(newItem)

		self.setModified(True)
		self.settings.mlogger.log("Group '%s' was created." % (groupName),
			logging.DEBUG, "GUI IO")

	def createGroupWithCheck(self):
		"""
		Slot to create a password group.
		"""
		dialog = AddGroupDialog(self.pwMap.groups, self.settings)
		if not dialog.exec_():
			return
		groupName = dialog.newGroupName()
		self.createGroup(groupName)

	def editGroup(self, item, groupNameOld, groupNameNew):
		"""
		Slot to edit name a password group.
		"""
		groupNew = self.pwMap.renameGroup(groupNameOld, groupNameNew)
		self.deleteGroup(item)
		self.createGroup(groupNameNew, groupNew)
		self.settings.mlogger.log("Group '%s' was renamed to '%s'." % (groupNameOld, groupNameNew),
			logging.DEBUG, "GUI IO")

	def editGroupWithCheck(self, item):
		"""
		Slot to edit name a password group.
		"""
		groupNameOld = encoding.normalize_nfc(item.text())
		dialog = AddGroupDialog(self.pwMap.groups, self.settings)
		dialog.setWindowTitle("Edit group name")
		dialog.groupNameLabel.setText("New name for group")
		dialog.setNewGroupName(groupNameOld)
		if not dialog.exec_():
			return

		groupNameNew = dialog.newGroupName()
		self.editGroup(item, groupNameOld, groupNameNew)

	def deleteGroup(self, item):  # without checking user
		groupName = encoding.normalize_nfc(item.text())
		self.selectedGroup = None
		del self.pwMap.groups[groupName]

		itemIdx = self.groupsModel.indexFromItem(item)
		self.groupsModel.takeRow(itemIdx.row())
		self.passwordTable.setRowCount(0)
		self.groupsTree.clearSelection()

		self.setModified(True)
		self.settings.mlogger.log("Group '%s' was deleted." % (groupName),
			logging.DEBUG, "GUI IO")

	def deleteGroupWithCheck(self, item):
		msgBox = QMessageBox(text="Are you sure about delete?", parent=self)
		msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
		res = msgBox.exec_()

		if res != QMessageBox.Yes:
			return

		self.deleteGroup(item)

	def deletePassword(self, item):
		msgBox = QMessageBox(text="Are you sure about delete?", parent=self)
		msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
		res = msgBox.exec_()

		if res != QMessageBox.Yes:
			return

		row = self.passwordTable.row(item)
		self.passwordTable.removeRow(row)
		group = self.pwMap.groups[self.selectedGroup]
		group.removeEntry(row)

		self.passwordTable.resizeRowsToContents()
		self.passwordTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
		self.passwordTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		self.passwordTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
		self.setModified(True)
		self.settings.mlogger.log("Row '%d' was deleted." % (row),
			logging.DEBUG, "GUI IO")

	def logCache(self, row):
		item = self.passwordTable.item(row, self.CACHE_IDX)
		cachedTuple = item.data(Qt.UserRole)
		if cachedTuple is None:
			cachedPassword, cachedComments = (None, None)
		else:
			cachedPassword, cachedComments = cachedTuple
		if cachedPassword is not None:
			cachedPassword = u'***'
		if cachedComments is not None:
			cachedComments = cachedComments[0:3] + u'...'
		self.settings.mlogger.log("Cache holds '%s' and '%s'." %
			(cachedPassword, cachedComments), logging.DEBUG, "Cache")

	def cachePasswordComments(self, row, password, comments):
		item = self.passwordTable.item(row, self.CACHE_IDX)
		item.setData(Qt.UserRole, QVariant((password, comments)))

	def cachedPassword(self, row):
		"""
		Retrieve cached password for given row of currently selected group.
		Returns password as string or None if no password cached.
		"""
		item = self.passwordTable.item(row, self.CACHE_IDX)
		cachedTuple = item.data(Qt.UserRole)
		if cachedTuple is None:
			cachedPassword, cachedComments = (None, None)
		else:
			cachedPassword, cachedComments = cachedTuple
		return cachedPassword

	def cachedComments(self, row):
		"""
		Retrieve cached comments for given row of currently selected group.
		Returns comments as string or None if no coments cached.
		"""
		item = self.passwordTable.item(row, self.CACHE_IDX)
		cachedTuple = item.data(Qt.UserRole)
		if cachedTuple is None:
			cachedPassword, cachedComments = (None, None)
		else:
			cachedPassword, cachedComments = cachedTuple
		return cachedComments

	def cachedOrDecryptPassword(self, row):
		"""
		Try retrieving cached password for item in given row, otherwise
		decrypt with Trezor.
		"""
		cached = self.cachedPassword(row)

		if cached is not None:
			return cached
		else:  # decrypt with Trezor
			group = self.pwMap.groups[self.selectedGroup]
			pwEntry = group.entry(row)
			encPwComments = pwEntry[1]

			decryptedPwComments = self.pwMap.decryptPassword(encPwComments, self.selectedGroup)
			lngth = int(decryptedPwComments[0:4])
			decryptedPassword = decryptedPwComments[4:4+lngth]
			decryptedComments = decryptedPwComments[4+lngth:]
			# while we are at it, cache the comments too
			self.cachePasswordComments(row, decryptedPassword, decryptedComments)
			self.settings.mlogger.log("Decrypted password and comments "
				"for '%s', row '%d'." % (pwEntry[0], row),
				logging.DEBUG, "GUI IO")
		return decryptedPassword

	def cachedOrDecryptComments(self, row):
		"""
		Try retrieving cached comments for item in given row, otherwise
		decrypt with Trezor.
		"""
		cached = self.cachedComments(row)

		if cached is not None:
			return cached
		else:  # decrypt with Trezor
			group = self.pwMap.groups[self.selectedGroup]
			pwEntry = group.entry(row)
			encPwComments = pwEntry[1]

			decryptedPwComments = self.pwMap.decryptPassword(encPwComments, self.selectedGroup)
			lngth = int(decryptedPwComments[0:4])
			decryptedPassword = decryptedPwComments[4:4+lngth]
			decryptedComments = decryptedPwComments[4+lngth:]
			self.cachePasswordComments(row, decryptedPassword, decryptedComments)
			self.settings.mlogger.log("Decrypted password and comments "
				"for '%s', row '%d'." % (pwEntry[0], row),
				logging.DEBUG, "GUI IO")
		return decryptedComments

	def showPassword(self, item):
		# check if this password has been decrypted, use cached version
		row = self.passwordTable.row(item)
		self.logCache(row)
		try:
			decryptedPassword = self.cachedOrDecryptPassword(row)
		except CallException:
			return
		item = QTableWidgetItem(decryptedPassword)

		self.passwordTable.setItem(row, self.PASSWORD_IDX, item)

	def showComments(self, item):
		# check if this password has been decrypted, use cached version
		row = self.passwordTable.row(item)
		try:
			decryptedComments = self.cachedOrDecryptComments(row)
		except CallException:
			return
		item = QTableWidgetItem(decryptedComments)

		self.passwordTable.setItem(row, self.COMMENTS_IDX, item)

	def createPassword(self):
		"""
		Slot to create key-value password entry.
		"""
		if self.selectedGroup is None:
			return
		group = self.pwMap.groups[self.selectedGroup]
		dialog = AddPasswordDialog(self.pwMap.trezor, self.settings)
		if not dialog.exec_():
			return

		plainPw = dialog.pw1()
		plainComments = dialog.comments()
		if len(plainPw) + len(plainComments) > basics.MAX_SIZE_OF_PASSWDANDCOMMENTS:
			self.settings.mlogger.log("Password and/or comments too long. "
				"Combined they must not be larger than %d." %
				basics.MAX_SIZE_OF_PASSWDANDCOMMENTS,
				logging.CRITICAL, "User IO")
			return

		row = self.passwordTable.rowCount()
		self.passwordTable.setRowCount(row+1)
		item = QTableWidgetItem(dialog.key())
		pwItem = QTableWidgetItem("*****")
		commentsItem = QTableWidgetItem("*****")
		self.passwordTable.setItem(row, self.KEY_IDX, item)
		self.passwordTable.setItem(row, self.PASSWORD_IDX, pwItem)
		self.passwordTable.setItem(row, self.COMMENTS_IDX, commentsItem)

		plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments
		encPw = self.pwMap.encryptPassword(plainPwComments, self.selectedGroup)
		bkupPw = self.pwMap.backupKey.encryptPassword(plainPwComments)
		group.addEntry(dialog.key(), encPw, bkupPw)

		self.cachePasswordComments(row, plainPw, plainComments)

		self.passwordTable.resizeRowsToContents()
		self.passwordTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
		self.passwordTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		self.passwordTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
		self.setModified(True)
		self.settings.mlogger.log("Password and comments entry "
			"for '%s', row '%d' was created." % (dialog.key(), row),
			logging.DEBUG, "GUI IO")

	def editPassword(self, item):
		row = self.passwordTable.row(item)
		group = self.pwMap.groups[self.selectedGroup]
		try:
			decrypted = self.cachedOrDecryptPassword(row)
			decryptedComments = self.cachedOrDecryptComments(row)
		except CallException:
			return

		dialog = AddPasswordDialog(self.pwMap.trezor, self.settings)
		entry = group.entry(row)
		dialog.keyEdit.setText(encoding.normalize_nfc(entry[0]))
		dialog.pwEdit1.setText(encoding.normalize_nfc(decrypted))
		dialog.pwEdit2.setText(encoding.normalize_nfc(decrypted))
		doc = QTextDocument(encoding.normalize_nfc(decryptedComments), parent=self)
		dialog.commentsEdit.setDocument(doc)

		if not dialog.exec_():
			return

		item = QTableWidgetItem(dialog.key())
		pwItem = QTableWidgetItem("*****")
		commentsItem = QTableWidgetItem("*****")
		self.passwordTable.setItem(row, self.KEY_IDX, item)
		self.passwordTable.setItem(row, self.PASSWORD_IDX, pwItem)
		self.passwordTable.setItem(row, self.COMMENTS_IDX, commentsItem)

		plainPw = dialog.pw1()
		plainComments = dialog.comments()
		if len(plainPw) + len(plainComments) > basics.MAX_SIZE_OF_PASSWDANDCOMMENTS:
			self.settings.mlogger.log("Password and/or comments too long. "
				"Combined they must not be larger than %d." %
				basics.MAX_SIZE_OF_PASSWDANDCOMMENTS,
				logging.CRITICAL, "User IO")
			return

		plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments

		encPw = self.pwMap.encryptPassword(plainPwComments, self.selectedGroup)
		bkupPw = self.pwMap.backupKey.encryptPassword(plainPwComments)
		group.updateEntry(row, dialog.key(), encPw, bkupPw)

		self.cachePasswordComments(row, plainPw, plainComments)

		self.setModified(True)
		self.settings.mlogger.log("Password and comments entry "
			"for '%s', row '%d' was edited." % (dialog.key(), row),
			logging.DEBUG, "GUI IO")

	def copyPasswordFromSelection(self):
		"""
		Copy selected password to clipboard. Password is decrypted if
		necessary.
		"""
		indexes = self.passwordTable.selectedIndexes()
		if not indexes:
			return

		# there will be more indexes as the selection is on a row
		row = indexes[0].row()
		item = self.passwordTable.item(row, self.PASSWORD_IDX)
		self.copyPasswordFromItem(item)

	def copyPasswordFromItem(self, item):
		row = self.passwordTable.row(item)
		try:
			decryptedPassword = self.cachedOrDecryptPassword(row)
		except CallException:
			return

		self.clipboard.setText(decryptedPassword)
		# Do not log contents of clipboard, contains secrets!
		self.settings.mlogger.log("Copied text to clipboard.", logging.DEBUG,
			"Clipboard")
		if basics.CLIPBOARD_TIMEOUT_IN_SEC > 0:
			self.timer.start(basics.CLIPBOARD_TIMEOUT_IN_SEC*1000)  # cancels previous timer

	def copyCommentsFromItem(self, item):
		row = self.passwordTable.row(item)
		try:
			decryptedComments = self.cachedOrDecryptComments(row)
		except CallException:
			return

		self.clipboard.setText(decryptedComments)
		# Do not log contents of clipboard, contains secrets!
		self.settings.mlogger.log("Copied text to clipboard.", logging.DEBUG,
			"Clipboard")
		if basics.CLIPBOARD_TIMEOUT_IN_SEC > 0:
			self.timer.start(basics.CLIPBOARD_TIMEOUT_IN_SEC*1000)  # cancels previous timer

	def clearClipboard(self):
		self.clipboard.clear()
		self.timer.stop()  # cancels previous timer
		self.settings.mlogger.log("Clipboard cleared.", logging.DEBUG,
			"Clipboard")

	def loadPasswords(self, item):
		"""
		Slot that should load items for group that has been clicked on.
		"""
		self.passwordTable.clear()  # clears cahce, but also clears the header, the 3 titles
		headerKey = QTableWidgetItem(u"Key")
		headerValue = QTableWidgetItem(u"Password/Value")
		headerComments = QTableWidgetItem(u"Comments")
		self.passwordTable.setColumnCount(self.NO_OF_PASSWDTABLE_COLUMNS)
		self.passwordTable.setHorizontalHeaderItem(self.KEY_IDX, headerKey)
		self.passwordTable.setHorizontalHeaderItem(self.PASSWORD_IDX, headerValue)
		self.passwordTable.setHorizontalHeaderItem(self.COMMENTS_IDX, headerComments)

		groupName = encoding.normalize_nfc(item.text())
		self.selectedGroup = groupName
		group = self.pwMap.groups[groupName]
		self.passwordTable.setRowCount(len(group.entries))

		i = 0
		for key, encValue, bkupValue in group.entries:
			item = QTableWidgetItem(key)
			pwItem = QTableWidgetItem("*****")
			commentsItem = QTableWidgetItem("*****")
			self.passwordTable.setItem(i, self.KEY_IDX, item)
			self.passwordTable.setItem(i, self.PASSWORD_IDX, pwItem)
			self.passwordTable.setItem(i, self.COMMENTS_IDX, commentsItem)
			i = i+1

		self.passwordTable.resizeRowsToContents()
		self.passwordTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
		self.passwordTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
		self.passwordTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
		self.settings.mlogger.log("Loaded password group '%s'." % (groupName),
			logging.DEBUG, "GUI IO")

	def loadPasswordsBySelection(self):
		proxyIdx = self.groupsTree.currentIndex()
		itemIdx = self.groupsFilter.mapToSource(proxyIdx)
		selectedItem = self.groupsModel.itemFromIndex(itemIdx)

		if not selectedItem:
			return

		self.loadPasswords(selectedItem)

	def filterGroups(self, substring):
		"""
		Filter groupsTree view to have items containing given substring.
		"""
		self.groupsFilter.setFilterFixedString(substring)
		self.groupsTree.sortByColumn(0, Qt.AscendingOrder)

	def printAbout(self):
		"""
		Show window with about and version information.
		"""
		msgBox = QMessageBox(QMessageBox.Information, "About",
			"About <b>TrezorPass</b>: <br><br>TrezorPass is a safe " +
			"Password Manager application for people owning a Trezor who prefer to " +
			"keep their passwords local and not on the cloud. All passwords are " +
			"stored locally in a single file.<br><br>" +
			"<b>" + basics.NAME + " Version: </b>" + basics.VERSION_STR +
			" from " + basics.VERSION_DATE_STR +
			"<br><br><b>Python Version: </b>" + sys.version.replace(" \n", "; ") +
			"<br><br><b>Qt Version: </b>" + QT_VERSION_STR +
			"<br><br><b>PyQt Version: </b>" + PYQT_VERSION_STR, parent=self)
		msgBox.setIconPixmap(QPixmap("icons/TrezorPass.svg"))
		msgBox.exec_()

	def saveBackup(self):
		"""
		First it saves any pending changes to the pwdb database file. Then it uses an operating system call
		to copy the file appending a timestamp at the end of the file name.
		"""
		if self.modified:
			self.saveDatabase()
		backupFilename = self.settings.dbFilename + u"." + time.strftime('%Y%m%d%H%M%S')
		copyfile(self.settings.dbFilename, backupFilename)
		self.settings.mlogger.log("Backup of the encrypted database file has been created "
			"and placed into file \"%s\" (%d bytes)." % (backupFilename, os.path.getsize(backupFilename)),
			logging.INFO, "User IO")

	def importCsv(self):
		"""
		Read a properly formated CSV file from disk
		and add its contents to the current entries.

		Import format in CSV should be : group, key, password, comments

		There is no error checking, so be extra careful.

		Make a backup first.

		Entries from CSV will be *added* to existing pwdb. If this is not desired
		create an empty pwdb file first.

		GroupNames are unique, so if a groupname exists then
		key-password-comments tuples are added to the already existing group.
		If a group name does not exist, a new group is created and the
		key-password-comments tuples are added to the newly created group.

		Keys are not unique. So key-password-comments are always added.
		If a key with a given name existed before and the CSV file contains a
		key with the same name, then the key-password-comments is added and
		after the import the given group has 2 keys with the same name.
		Both keys exist then, the old from before the import, and the new one from the import.

		Examples of valid CSV file format: Some example lines
		First Bank account,login,myloginname,	# no comment
		foo@gmail.com,2-factor-authentication key,abcdef12345678,seed to regenerate 2FA codes	# with comment
		foo@gmail.com,recovery phrase,"passwd with 2 commas , ,",	# with comma
		foo@gmail.com,large multi-line comments,,"first line, some comma,
		second line"
		"""
		if self.modified:
			self.saveDatabase()
		copyfile(self.settings.dbFilename, self.settings.dbFilename + ".beforeCsvImport.backup")
		self.settings.mlogger.log("WARNING: You are about to import entries from a "
			"CSV file into your current password-database file. For safety "
			"reasons please make a backup copy now.\nFurthermore, this"
			"operation can be slow, so please be patient.", logging.NOTSET,
			"CSV import")
		dialog = QFileDialog(self, "Select CSV file to import",
			"", "CSV files (*.csv)")
		dialog.setAcceptMode(QFileDialog.AcceptOpen)

		res = dialog.exec_()
		if not res:
			return

		fname = encoding.normalize_nfc(dialog.selectedFiles()[0])
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
					groupName = encoding.normalize_nfc(csvEntry[0])
					key = encoding.normalize_nfc(csvEntry[1])
					plainPw = encoding.normalize_nfc(csvEntry[2])
					plainComments = encoding.normalize_nfc(csvEntry[3])
				except Exception as e:
					raise IOError("Critical Error: Could not import CSV file. "
						"CSV Entry: len=%d (should be 4) element[0]=%s. (%s)" %
							(len(csvEntry), csvEntry[0], e))

				groupNames = self.pwMap.groups.keys()
				if groupName not in groupNames:  # groups are unique
					self.pwMap.addGroup(groupName)
					item = QStandardItem(groupName)
					self.groupsModel.appendRow(item)

				if len(plainPw) + len(plainComments) > basics.MAX_SIZE_OF_PASSWDANDCOMMENTS:
					self.settings.mlogger.log("Password and/or comments too long. "
						"Combined they must not be larger than %d." % basics.MAX_SIZE_OF_PASSWDANDCOMMENTS, logging.NOTSET,
						"CSV import")
					return
				group = self.pwMap.groups[groupName]
				plainPwComments = ("%4d" % len(plainPw)) + plainPw + plainComments
				encPw = self.pwMap.encryptPassword(plainPwComments, groupName)
				bkupPw = self.pwMap.backupKey.encryptPassword(plainPwComments)
				group.addEntry(key, encPw, bkupPw)  # keys are not unique, multiple items with same key are allowed
			self.groupsTree.sortByColumn(0, Qt.AscendingOrder)
			self.setModified(True)

		self.settings.mlogger.log("TrezorPass has finished importing CSV file "
			"from \"%s\" into \"%s\"." % (fname, self.settings.dbFilename), logging.INFO,
			"CSV import")

	def exportCsv(self):
		"""
		Uses backup key encrypted by Trezor to decrypt all passwords
		at once and export them into a single paintext CSV file.

		Export format is CSV: group, key, password, comments
		"""
		self.settings.mlogger.log("WARNING: During backup/export all passwords will be "
			"written in plaintext to disk. If possible you should consider performing this "
			"operation on an offline or air-gapped computer. Be aware of the risks.",
			logging.NOTSET,	"CSV export")
		dialog = QFileDialog(self, "Select backup export file",
			"", "CSV files (*.csv)")
		dialog.setAcceptMode(QFileDialog.AcceptSave)

		res = dialog.exec_()
		if not res:
			return

		fname = encoding.normalize_nfc(dialog.selectedFiles()[0])
		backupKey = self.pwMap.backupKey
		try:
			privateKey = backupKey.unwrapPrivateKey()
		except CallException:
			return

		with open(fname, "w") as f:
			csv.register_dialect("escaped", doublequote=False, escapechar='\\')
			writer = csv.writer(f, dialect="escaped")
			sortedGroupNames = sorted(self.pwMap.groups.keys())
			for groupName in sortedGroupNames:
				group = self.pwMap.groups[groupName]
				for entry in group.entries:
					key, _, bkupPw = entry
					decryptedPwComments = backupKey.decryptPassword(bkupPw, privateKey)
					lngth = int(decryptedPwComments[0:4])
					password = decryptedPwComments[4:4+lngth]
					comments = decryptedPwComments[4+lngth:]
					# if we don't escape than the 2-letter string '"\' will
					# lead to an exception on import
					csvEntry = (encoding.escape(groupName),
						encoding.escape(key),
						encoding.escape(password),
						encoding.escape(comments))
					# all 4 elements in the 4-tuple are of type string
					# Py2-vs-Py3: writerow() in Py2 implements on 7-bit unicode
					# In py3 it implements full unicode.
					# That means if there is a foreign character, writerow()
					# in Py2 reports the exception:
					# "UnicodeEncodeError: 'ascii' codec can't encode character u'\xxx' in position xx
					# In Py2 we need to convert it back to bytes!
					if sys.version_info[0] < 3:  # Py2-vs-Py3:
						# the byte-conversion un-escapes, so we have to escape again!
						csvEntry = (encoding.escape(encoding.tobytes(groupName)),
							encoding.escape(encoding.tobytes(key)),
							encoding.escape(encoding.tobytes(password)),
							encoding.escape(encoding.tobytes(comments)))
					writer.writerow(csvEntry)

		self.settings.mlogger.log("TrezorPass has finished exporting CSV file "
			"from \"%s\" to \"%s\"." % (self.settings.dbFilename, fname), logging.INFO,
			"CSV export")

	def saveDatabase(self):
		"""
		Save main database file.
		"""
		self.pwMap.save(self.dbFilename)
		self.setModified(False)
		self.settings.mlogger.log("TrezorPass password database file was "
			"saved to '%s'." % (self.dbFilename), logging.DEBUG, "GUI IO")

	def closeEvent(self, event):
		if self.modified:
			msgBox = QMessageBox(text="Password database is modified. Save on exit?", parent=self)
			msgBox.setStandardButtons(QMessageBox.Yes |
				QMessageBox.No | QMessageBox.Cancel)
			reply = msgBox.exec_()

			if not reply or reply == QMessageBox.Cancel:
				event.ignore()
				return
			elif reply == QMessageBox.Yes:
				self.saveDatabase()

		event.accept()

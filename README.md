# TrezorPass hardware-backed password manager


![TrezorPass icon](https://github.com/8go/TrezorPass/blob/master/icons/TrezorPass.png)

TrezorPass is a PyQt-based password manager that uses the [Trezor](http://www.trezor.io/)
hardware token to do encryption of passwords. It is similar to KeepassX or
kwalletmanager in function. It can store passwords, logons, URLs, PINs, comments, etc.

The Password database is stored in encrypted form in a single file on computer. 
No access to internet is required for its use. It allows an unlimited
count of password entries to be stored and enables the possibility of recovery
if your original Trezor is misplaced (mnemonic and passphrase are required to recover).

Note that this is alpha software.

Trezor must be already set up to use passphrase.

Below  a sample screenshot. More screenshots [here](tree/master/screenshots-version-2).

![Screenshot](https://github.com/8go/TrezorPass/blob/master/screenshots-version-2/trezorpass-screenshot-mainwindow-mainmenu.png)

# Security features

  * **secure**: even in the worst case with a virus on your computer, that has access to your 
    keyboard, your applications and your memory, only the passwords
    you are copying-and-pasting can be stolen. All unused passwords 
    remain safely secured by Trezor
  * works offline, no cloud service required
  * portable, stores all information in a single file
  * symmetric password encryption key never leaves the Trezor
  * button confirmation on Trezor is required to activate decryption of a password 
  * upon requesting password decryption, user sees on Trezor's display decryption
    of which password group is requested before confirmation
  * export of passwords to a CSV file is possible, also requires explicit button confirmation
  * import of passwords from a CSV file is possible, allowing migration from other password
    managers
  * a backup function for backing up the encrypted password database is provided for convenience
  * 10 seconds after copying a password to the clipboard the clipboard is automatically cleared again
  * if Trezor is lost, recovery from seed on a new Trezor and using the same
    password will also recover encrypted password database (in theory recovery
    can be done without Trezor, but such script is not yet written)

# Runtime requirements

  * PyCrypto
  * PyQt4
  * [trezorlib from python-trezor](https://github.com/trezor/python-trezor)

# Building

Even though the whole code is in Python, there are few Qt .ui form files that
need to be transformed into Python files. There's Makefile, you just need to run

    make

## Build requirements

PyQt4 development tools are necessary, namely `pyuic4` (look for packages named
like `pyqt4-dev-tools` or `PyQt4-devel`).

# Running

Run:

    python TrezorPass.py

# How export to CSV works

Each password is encrypted and stored twice. Once with symmetric AES-CBC function
of Trezor that always requires button confirmation on device to decrypt. Second
encryption is done to public RSA key, whose private counterpart is encrypted
with Trezor. Backup requires private RSA to be decrypted and then used to decrypt
the passwords.


# TrezorPass hardware-backed password manager


![TrezorPass icon](icons/TrezorPass.png)

TrezorPass is a PyQt-based password manager that uses the [Trezor](http://www.trezor.io/)
hardware token to do encryption of passwords. It is similar to KeepassX or
kwalletmanager in function. It can store passwords, logons, URLs, PINs, comments, etc.

The Password database is stored in encrypted form in a single file on computer. 
No access to internet is required for its use. It allows an unlimited
count of password entries to be stored and enables the possibility of recovery
if your original Trezor is misplaced (mnemonic and passphrase are required to recover).

Note that this is alpha software.

Trezor must be already set up to use passphrase.

Below  a sample screenshot. More screenshots [here](../../tree/master/screenshots-version-2).

![Screenshot](screenshots-version-2/trezorpass-screenshot-mainwindow-mainmenu.png)

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
with Trezor. Export requires private RSA to be decrypted and then used to decrypt
the passwords. The RSA key is managed internally, so that you do not need to 
worry about it. 

# FAQ - Frequently Asked Questions

**Question:** I read something about an RSA key somewhere? Do I need to create it? Can I use my own? Where is it? How many bits is it?

**Answer:** 

* No, you do not need to create it, it is created automatically for you. 
* No, you cannot use your own existing RSA key.
* It is created and stored Trezor-encrypted in the pwdb database password file.
* It is a 4096-bit RSA keypair.
- - -
**Question:** What crypto technology is used?

**Answer:** Various.

* 256-bit AES
* 4096-bit RSA
* [Trezor](https://www.trezor.io)
- - -
**Question:** Is there a config file or a settings file?

**Answer:** No, there are no config and no settings files. The only vlue stored outside of the pwdb password database file is its filename (full path). 
This string is stored in the QQtCore.QSettings.
- - -
**Question:** Does TrezorPass require online connectivity, Internet access? 

**Answer:** No.
- - -
**Question:** Does TrezorPass require a Google, DropBox or similar cloud service provider account? 

**Answer:** No.
- - -
**Question:** How many files are there? 

**Answer:** For the data there is always just one file, the pwdb password database file. For the TrezorPass executable it depends. At best there is only a single executable. This single-file-executable is provided for you for Linux 64-bit. On other platforms you can create it yourself with [pyinstaller](www.pyinstaller.org) and [pyinstaller](https://github.com/pyinstaller/pyinstaller/wiki). So, with 2 files (one executable and one datafile) you can do everything.
- - -
**Question:** In which language is TrezorPass written? 

**Answer:** [Python](https://www.python.org/).
- - -
**Question:** Do I need to have a [Trezor](https://www.trezor.io/) in order to use TrezorPass? 

**Answer:** Yes, a Trezor is required.
- - -
**Question:** How big is the single-file-executable for Linux? 

**Answer:** Currently around 23M.
- - -
**Question:** How many passwords can I store in TrezorPass? 

**Answer:** For practical purposes, unlimited. Let's just say "thousands".
- - -
**Question:** Is there a limit on the password size or comment size? 

**Answer:** Currently, the password length is limited to 512 characters and the password+comments to 4096 characters. You can increment these limits in the software if you really need larger values.
- - -
**Question:** Can I see the source code? 

**Answer:** Yes, this is an open source software project. You can find and download all source code from [Github](https://github.com/hiviah/TrezorPass) or any of its forks.
- - -
**Question:** Does the TrezorPass contain ads? 

**Answer:** No.
- - -
**Question:** Does the TrezorPass cost money? 

**Answer:** No. It is free, libre, and open source.
- - -
**Question:** Does TrezorPass call home? Send any information anywhere? 

**Answer:** No. Never. You can also use it on an air-gapped computer if you want to. It does not use any network calls at any time.
- - -
**Question:** Does TrezorPass have a backdoor? 

**Answer:** No. Read the source code to convince yourself.
- - -
**Question:** How can I know that TrezorPass does not contain a virus?

**Answer:** Download the source from [Github](https://github.com/hiviah/TrezorPass) and inspect the souce code for viruses. Don't download it from unreliable sources.
- - -
**Question:** How can someone steal **all** my passwords? 

**Answer:** In order to get access to all your passwords one would need to a) steal your physical Trezor device, and b) steal your TrezorPass password database file, and) know or steal your Trezor passphrase for TrezorPass (=TrezorPass master passphrase) and d) know or steal your Trezor PIN code. Alternatively, one would need to a) steal your 24 Trezor seed words, and b) steal your TrezorPass password database file, and) know or steal your Trezor passphrase for TrezorPass (=TrezorPass master passphrase).
- - -
**Question:** Can a **remote** hacker or a virus on my computer steal **all** my passwords?

**Answer:** A remote hacker cannot have access to your physical trezor device. A remote hacker should not have access to your 24 Trezor seed words (as those should never be stored online). Under these conditions a remote hacker **cannot** steal **all** your passwords at once.
- - -
**Question:** Can a keyboard logger steal a password?

**Answer:** Not if you are careful. Passwords can be created with a "Generate random password" button click without the use of a keyboard. Using an existing password is usually done with copy-and-paste, ie. ^C and ^V. So, again, you can use a password without using the keyboard. The keyboard logger only sees that you have used ^C and ^V.
- - -
**Question:** Can a screen grabber or a person looking over my shoulder steal a password?

**Answer:** Not if you are careful. Passwords can be created with a "Generate random password" button click without the use of a keyboard. Passwords are printed as '*' on the screen. If you use it via copy-and-paste and paste it to, say, a safe web login or a login screen, there as well the password is printed as '*'. So, no information about the password is normally visible on the screen. However, if you paste it to, say, a plaintext text editor, then you and anyone else watching can see it on your screen.
- - -
**Question:** What can be stolen? How can it be stolen?

**Answer:** A virus or malware on your computer can steal **individual** passwords, but never **all** of them. Say you have an email account with company X. There you have a username, a password, a security question, and a recovery email address. Say, you have stores all 4 items in TrezorPass. Say, you have some 99 other passwords from other accounts. Now you connect with your computer to company X's website to read your email. You copy and paste your user name and your password from TrezorPass to the webpage to enter your mail account. When you copy your username you have to give permissions on trezor by clicking the confirmation button on the Trezor. The same when you copy the password to the clipboard. Now at this moment the username and password are in the memory of your computer. Now assume you have a virus that reads your computers memory. It can now copy your username and password and send it off to his server. Later the hacker can enter into your mail account and read your email. (This is why you should have [2FA](https://en.wikipedia.org/wiki/2FA) or [FIDO/U2F](https://en.wikipedia.org/wiki/U2F) protection on your accounts). Note that the hacker could neither steal your security question nor your recovery email address. So, in our example the hacker most likely could not change your email password (as he does not have the security question answer). And of course, the hacker could not steal any of the other 99 passwords from the other accounts. So, in short, at best a hacker can steal the items that you unlock with your Trezor and only for a short time while they are in memory. The only way to protect yourself from this is by using 2FA and/or FIDO/U2F where there are 2 factors and the hacker can only steal one preventing the hacker from entering into your accounts even when he is in possession of one factor.
- - -
**Question:** Is TrezorPass available in my language?

**Answer:** It is only available in English.
- - -
**Question:** Is TrezorPass portable?

**Answer:** Yes. You can have all information on 2 files: the TrezorPass application and the password database file. Copy the 2 files (executable and data) onto a USB stick or SD card and carry them with you together with your Trezor. (Maybe in the future the files might be stored on the Trezor 2 on-device storage? Who knows?)
- - -
**Question:** Can I use TrezorPass on multiple computers? Can I sync it on multiple devices/computers?

**Answer:** Yes. There are many ways to do with various degrees of convenience. 

* One solution might be to carry the password database always with you on an SD card or USB stick. 
* Another simple way is just to copy the software and the password database to 2 or more computers/devices. That is static and the password database is not synchronized.
* Imagine you have a home network or a small office network. You might place the password database file to a shared disk, a shared server, a shared NAS or similar. Thereby all computers/devices on this local network have access to the same password database. All computers are in sync because there is only a single shared copy of the password database. In this scenario TrezorPass should be used by only one person at a time. Since you usually have only one Trezor that is usually no problem.
* You can sync the password database yourself between various computers/devices on one or multiple networks. On Linux you might use rsync or a multitude of other solutions. 
* You can sync the password database with known cloud service providers. E.g. you can use DropBox to sync the password database between all your devices. DropBox cannot read your database as it is encrypted. You can also give the password database some unassuming name like "photo.jpg" if you do not want to draw attention.
- - -
**Question:** Can I contribute to the project?

**Answer:** Yes. It is open source. Go to [Github](https://github.com/hiviah/TrezorPass).
- - -
**Question:** Can I migrate from another password manager such as KeePass or [Pass](https://www.passwordstore.org/) or others to TrezorPass?

**Answer:** Yes. But it is not a one-click or two-click affair.

* Step 1: export your passwords from the original password manager to a plaintext CSV or plain text file. You might want to do this on a secure or air-gapped computer if you have one available.
* Step 2: Modify the CSV file mannually or via script so that it follows the required TrezorPass CSV import standard. The required TrezorPass CSV import standard is very simple: 4-element-tuplets separated by comma (,) and possibly quoted ("). The 4-element tuplets are: group name, key, password, comments
* Step 3: import this CSV file into TrezorPass. All entries found in the CSV file will be added to the existing database. 
* Examples of a valid CSV file format for import: Some sample lines

'''
First Bank account,login,myloginname,
foo@gmail.com,2-factor-authentication key,abcdef12345678,seed to regenerate 2FA codes
foo@gmail.com,recovery phrase,"passwd with 2 commas , ,",	
foo@gmail.com,large multi-line comments,,"first line, some comma, 
second line"
phone,PIN,1234,my phone PIN
'''

More details [here](https://github.com/8go/TrezorPass/pull/6).
- - -
**Question:** What if I lose my password database file?

**Answer:** Then you lost all your passwords. The passwords are **not** stored on the Trezor. The passwords are only stored in the password database file. So keep it safe. (Trezor 2 does not exist yet, but it might come with on-device storage in the future. In this future case you might store a copy of the password database file on the device. But even then you should keep a copy somewhere else as well.)
- - -
**Question:** Should I backup my password database file?

**Answer:** Yes you should. For convenience there is a backup function built-into TrezorPass. Use if frequently. For your safety keep a second (or third) copy on a different device/computer/SD-card/USB-stick.
- - -
**Question:** What if I lose my Trezor and my 24 Trezor seed words or my TrezorPass master password?

**Answer:** Then you will not be able to open your TrezorPass. For practical purposes you have lost all your passwords. Brute-forcing is not a viable work-around.
- - -
**Question:** On which platforms, operating systems is TrezorPass available?

**Answer:** On all platforms, operating systems where [Python](https://www.python.org/) and [PyQt](https://en.wikipedia.org/wiki/PyQt) is available: Windows, Linux, Unix, Mac OS X. Internet searches show Python and PyQt solutions for Android and iOS, but it has not been investigated or tested on Android or iOS.
- - -
**Question:** Are there any warranties or guarantees?

**Answer:** No, there are no warranties or guarantees whatsoever.
- - -
**Question:** More questions?

**Answer:** Let us know.
- - -

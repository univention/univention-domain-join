[toc]

# Building packages for Launchpad
1. Clone the git repo ([https://git.knut.univention.de/univention/univention-domain-join])
2. Checkout branch: `git checkout ubuntu24.04`
3. Build the source package `dpkg-buildpackage -S -us -uc`
4. Sign the source package
   - On omar, as root: `debsign -k D523B8FD547C464C9EA89D5B5E9F163B66AA3A17 *.changes`, Passwort: /etc/archive-keys/ucc.txt
5. For a new Ubuntu release:
   1. Login into Launchpad (Credentials in Dokuwiki)
   2. [https://launchpad.net/~univention-dev/+archive/ubuntu/ppa/+packages]() click on "Copy packages", select the newest version, under "Destination Series" select the new Ubuntu Version
   3. With `add-apt-repository ppa:univention-dev/ppa` and `apt-get` the new package should now be visible
6. On Ubuntu, upload the signed package: `ppa:univention-dev/ppa univention-domain-join_[...].changes`
   - Credentials in Dokuwiki
   - If the error `gpg.errors.BadSignatures: <Key finger print>: No public key` appears, import the Univention public key:
      - `apt-key adv --keyserver keyserver.ubuntu.com --recv-keys key_finger_print` or
     - `gpg --keyserver hkps://keyserver.ubuntu.com --receive-keys D523B8FD547C464C9EA89D5B5E9F163B66AA3A17`
7. Make sure the package has been built correctly
   - If not: Check mails of packages@univention.de

# Building binary packages
See GitLab pipeline

# Testing
- https://git.knut.univention.de/univention/ucs/-/tree/5.0-2/test/product-tests/domain-join

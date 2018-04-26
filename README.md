# Univention Domain Join

This is an assistant for joining Ubuntu computers into Univention Corporate
Server (UCS) domains. It will perform the following steps for you:

- Create an LDAP object for your Ubuntu computer on UCS
- Configure DNS
- Configure Kerberos
- Configure the login manager, if necessary
- Configure PAM
- Configure SSSD

Univention Domain Join supports the following Linux distributions:

- Ubuntu 18.04 LTS („Bionic Beaver“)
- Ubuntu 17.10 („Artful Aardvark“)
- Ubuntu 16.04 LTS („Xenial Xerus“)
- Ubuntu 14.04 LTS („Trusty Tahr“)

Univention Domain Join supports the Gnome and Unity desktop environments. The
configuration of the login manager of other desktop environments may not work,
but can be skipped using the `--skip-login-manager` parameter of the
`univention-domain-join-cli` tool.

# Download and Installation

You can install Univention Domain Join assistant on Ubuntu via the [PPA of
Univention](https://launchpad.net/~univention-dev/+archive/ubuntu/ppa) using
these commands:

```shell
sudo add-apt-repository ppa:univention-dev/ppa
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install univention-domain-join
```

Run the assistant using the start menu. 

There is also a command line tool, which you can run with
`univention-domain-join-cli`. The command line tool can be installed separately
with the package `univention-domain-join-cli`.

# License

Univention Domain Join is built on top of many existing open source projects
which use their own licenses. The source code of all parts written by
Univention is licensed under the AGPLv3 . Please see the
[license file](./LICENSE) for more information.

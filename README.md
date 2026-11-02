# Univention Domain Join — RPM edition

This is a port of [univention-domain-join](https://github.com/univention/univention-domain-join)
(`ubuntu24.04` branch) to RPM based Linux distributions. It is an assistant for
joining client computers into Univention Corporate Server (UCS) domains. It will
perform the following steps for you:

- Create an LDAP object for your computer on UCS (UDM type `computers/linux`)
- Configure DNS
- Configure Kerberos
- Configure the login manager, if necessary
- Configure PAM
- Configure SSSD

Supported distributions:

- Fedora
- RHEL 8/9 (and rebuilds: CentOS Stream, Rocky Linux, AlmaLinux, Oracle Linux)

## Differences to the Debian/Ubuntu version

| Debian/Ubuntu                             | RPM edition                                        |
|-------------------------------------------|----------------------------------------------------|
| `pam-auth-update`, `/usr/share/pam-configs` | `authselect` with a custom `ucs` profile (`with-mkhomedir`, `pam_group`) |
| `update-ca-certificates`                  | `update-ca-trust` (`/etc/pki/ca-trust/source/anchors`) |
| `/etc/ldap/ldap.conf`                     | `/etc/openldap/ldap.conf`                          |
| UDM computer type `computers/ubuntu`      | `computers/linux`                                  |
| `lsb_release`                             | `/etc/os-release`                                  |
| `ntpdate`                                 | `ntpdate` → `sntp` → `chronyd` (first one found)   |
| `/etc/X11/default-display-manager`        | `display-manager.service` systemd symlink          |
| resolvconf / dhclient DNS configuration   | NetworkManager (`nmcli`) or direct `/etc/resolv.conf` |

## Installation

<!-- ### From the RPM package

Build the RPM and install it — all dependencies are pulled in automatically:

```
sudo dnf install rpm-build python3-devel python3-setuptools python3-pip -y
pip install build
python3 -m build --sdist .            # or: python3 setup.py sdist
rpmbuild -ta dist/univention-domain-join-cli-1.0.0.tar.gz
sudo dnf install ~/rpmbuild/RPMS/noarch/univention-domain-join-cli-1.0.0-1.*.noarch.rpm
``` -->

### With pip

```
sudo dnf install python3-dns python3-ldap openssh-clients sshpass \
    openldap-clients sssd sssd-ldap sssd-krb5 krb5-workstation authselect \
    oddjob-mkhomedir oddjob wget pip git -y
git clone https://github.com/mkomlaetou/univention-domain-join-rpm.git
cd univention-domain-join-rpm
sudo pip install .
sudo ln -sf /usr/local/bin/univention-domain-join-cli /usr/bin/univention-domain-join-cli
```

The symlink puts the command on root's PATH: pip installs scripts to
`/usr/local/bin`, which is not part of sudo's `secure_path` on
RHEL-likes, so `sudo univention-domain-join-cli` would not be found
otherwise. (The RPM package installs directly into `/usr/bin` and does
not need this step.)

## Usage

Run the tool as root and follow the prompts:

```
sudo univention-domain-join-cli
```

or, fully scripted:

```
sudo univention-domain-join-cli --dc-ip 10.0.0.1 --username Administrator --password-file /root/admin.pw
```

Run `univention-domain-join-cli --help` for all options. The command line
interface is compatible with the Debian/Ubuntu version, including
`--skip-login-manager`, `--force-ucs-dns`, `--domain` and `--dc-ip`.

Additionally, this port provides `--register-dns`: it registers an A record
(and, if a matching reverse zone exists, a PTR record) for the machine in
the UCS DNS zone. Registration only happens when the machine's primary IP
address is statically configured — DHCP clients are skipped, because a
record written at join time would go stale with the next lease.

With `--sudo-groups` you can grant domain groups sudo rights at join
time; the groups are written to `/etc/sudoers.d/50-ucs-domain-groups`
(validated with `visudo` before being installed):

```
sudo univention-domain-join-cli --dc-ip 10.0.0.1 --sudo-groups "Domain Admins,IT-Support"
```

`--sudo-groups` requires members to re-enter their password for sudo —
this is the recommended variant for human admins. The alternative
`--sudo-groups-nopasswd` grants passwordless sudo (`NOPASSWD: ALL`) and
is intended for automation accounts and lab machines only; passwordless
sudo removes the re-authentication barrier, so anyone hijacking a group
member's session gets instant root.

To leave the domain again, use `--disjoin`: it deletes the machine's
computer object on the DC (including its DNS records), restores the
pre-join configuration from the backup, reverts PAM to the stock
authselect profile, removes the UCS root certificate and stops SSSD:

```
sudo univention-domain-join-cli --disjoin --dc-ip 10.0.0.1
sudo univention-domain-join-cli --disjoin --local-only --yes  # local cleanup only
```

The GUI of the original project was not ported — only the CLI is provided.

Before anything is changed, a backup of all modified configuration files is
created in `/var/univention-backup/<timestamp>_domain-join/`. The log file is
written to `/var/log/univention/domain-join-cli.log`.

## Notes

- Home directories for domain users are created via `pam_oddjob_mkhomedir`
  (authselect feature `with-mkhomedir`); the `oddjobd` service is enabled
  automatically.
- The authselect profile `custom/ucs` is created as a copy of the stock `sssd`
  profile, with `pam_group.so` added so that domain users are put into the
  local groups listed in `/etc/security/group.conf` at login time.
- The UCS root certificate is stored at `/etc/univention/ssl/ucsCA/CAcert.pem`
  (same path as on Ubuntu clients, referenced by `sssd.conf`) and additionally
  added to the system trust store.

## Documentation

Full documentation — architecture, join flow, files modified on the
client, CLI reference, dependencies and troubleshooting — is available in
[docs/DOCUMENTATION.md](docs/DOCUMENTATION.md).

## License

This project is derived from univention-domain-join and is licensed under the
AGPLv3, like the original. See `LICENSES/AGPL-3.0-only.txt`.

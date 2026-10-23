Name:           univention-domain-join-cli
Version:        1.0.0
Release:        1%{?dist}
Summary:        Assistant for joining RPM based Linux clients into UCS domains

License:        AGPL-3.0-only
URL:            https://github.com/univention/univention-domain-join
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools

Requires:       python3
Requires:       python3-dns
Requires:       python3-ldap
Requires:       openssh-clients
Requires:       sshpass
Requires:       openldap-clients
Requires:       sssd
Requires:       sssd-ldap
Requires:       sssd-krb5
Requires:       krb5-workstation
Requires:       authselect
Requires:       oddjob-mkhomedir
Requires:       oddjob
Requires:       iproute
Requires:       wget

%description
An assistant for joining RPM based Linux clients (Fedora, RHEL, CentOS,
Rocky, AlmaLinux, Oracle Linux) into Univention Corporate Server (UCS)
domains. It will perform the following steps for you:

- Create an LDAP object for your computer on UCS
- Configure DNS
- Configure Kerberos
- Configure the login manager, if necessary
- Configure PAM (via authselect)
- Configure SSSD

This is a port of univention-domain-join for Debian/Ubuntu based systems.

%prep
%autosetup

%build
%py3_build

%install
%py3_install

%files
%license LICENSES/AGPL-3.0-only.txt
%doc README.md
%{_bindir}/univention-domain-join-cli
%{python3_sitelib}/univention_domain_join/
%{python3_sitelib}/univention_domain_join_cli-%{version}.dist-info/

%changelog
* Mon Oct 20 2026 Univention domain join RPM port - 1.0.0-1
- Initial RPM release, ported from univention-domain-join (ubuntu24.04 branch)

# Univention Domain Join
This is an assistant for joining Ubuntu computers into Univention Corporate
Server domains. It will perform the following steps for you:

- Create an LDAP object for your Ubuntu computer
- Configure DNS
- Configure Kerberos
- Configure the login manager, if necessary
- Configure PAM
- Configure SSSD

# Download and Installation
You can install the tool via the PPA of Univention using these commands:

```shell
sudo add-apt-repository ppa:univention-dev/ppa
sudo apt-get update
sudo apt-get install univention-domain-join
```

After that run the assistant using the start menu. There is also a command line
tool, which you can run with `univention-domain-join-cli`.

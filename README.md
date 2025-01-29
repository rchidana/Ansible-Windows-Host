# Ansible-Windows-Host Configuration

# Instructions to set up & control Windows Host

Ansible Documentation Reference --> https://docs.ansible.com/ansible/latest/os_guide/windows_winrm.html#windows-winrm <br>

On the Ubuntu Ansible Controller, install : <br>

### Ansible Controller

```
# Run these commands inside Ubuntu (Windows WSL)
sudo apt-get update -y
sudo apt-add-repository -y ppa:ansible/ansible
sudo apt-get update -y
sudo apt-get install ansible
ansible --version

# Let us try some adhoc commands against localhost
ansible localhost -m "ping"
ansible localhost -a "hostname"

# Install WinRM package (Python client for Windows Remote Management)
sudo apt-get -y install python3-winrm

```

### Windows Machine

##### Open Powershell with Administrator Privilege and run the following

```
# Modify firewall rule to let in IPv4 and IPv6 traffic
Enable-NetFirewallRule -DisplayName 'Virtual Machine Monitoring (Echo Request - ICMPv4-In)'
Enable-NetFirewallRule -DisplayName 'Virtual Machine Monitoring (Echo Request - ICMPv6-In)'

```
#### Follow WinRM instructions from Ansible Documentation <br>
https://docs.ansible.com/ansible/latest/os_guide/windows_winrm.html#winrm-setup <br>

```
# Enables the WinRM service and sets up the HTTP listener
Enable-PSRemoting -Force

# Opens port 5985 for all profiles
$firewallParams = @{
    Action      = 'Allow'
    Description = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]'
    Direction   = 'Inbound'
    DisplayName = 'Windows Remote Management (HTTP-In)'
    LocalPort   = 5985
    Profile     = 'Any'
    Protocol    = 'TCP'
}
New-NetFirewallRule @firewallParams

# Allows local user accounts to be used with WinRM
# This can be ignored if using domain accounts
$tokenFilterParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
New-ItemProperty @tokenFilterParams
```
Set up HTTPS with self-signed certificate <br>

```
# Create self signed certificate
$certParams = @{
    CertStoreLocation = 'Cert:\LocalMachine\My'
    DnsName           = $env:COMPUTERNAME
    NotAfter          = (Get-Date).AddYears(1)
    Provider          = 'Microsoft Software Key Storage Provider'
    Subject           = "CN=$env:COMPUTERNAME"
}
$cert = New-SelfSignedCertificate @certParams

# Create HTTPS listener
$httpsParams = @{
    ResourceURI = 'winrm/config/listener'
    SelectorSet = @{
        Transport = "HTTPS"
        Address   = "*"
    }
    ValueSet = @{
        CertificateThumbprint = $cert.Thumbprint
        Enabled               = $true
    }
}
New-WSManInstance @httpsParams

# Opens port 5986 for all profiles
$firewallParams = @{
    Action      = 'Allow'
    Description = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]'
    Direction   = 'Inbound'
    DisplayName = 'Windows Remote Management (HTTPS-In)'
    LocalPort   = 5986
    Profile     = 'Any'
    Protocol    = 'TCP'
}
New-NetFirewallRule @firewallParams
```
Verify if the listeners are up & running <br>

```
winrm enumerate winrm/config/Listener
```

Output should be similar to the following:

```
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Hostname
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint
    ListeningOn = 10.0.2.15, 127.0.0.1, 192.168.56.155, ::1, fe80::5efe:10.0.2.15%6, fe80::5efe:192.168.56.155%8, fe80::
ffff:ffff:fffe%2, fe80::203d:7d97:c2ed:ec78%3, fe80::e8ea:d765:2c69:7756%7

Listener
    Address = *
    Transport = HTTPS
    Port = 5986
    Hostname = SERVER2016
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint = E6CDAA82EEAF2ECE8546E05DB7F3E01AA47D76CE
    ListeningOn = 10.0.2.15, 127.0.0.1, 192.168.56.155, ::1, fe80::5efe:10.0.2.15%6, fe80::5efe:192.168.56.155%8, fe80::
ffff:ffff:fffe%2, fe80::203d:7d97:c2ed:ec78%3, fe80::e8ea:d765:2c69:7756%7

```
To double confirm, you can also check the status of "Windows Remote Management (WS-Management)" service in the Windows "Services" UI! <br>

Now, check if you can ping (ICMP) your windows machine from Ansible Controller <br>

```
ping <IP-ADDRESS-OF-WINDOWS-MACHINE>
```

Create an inventory (/etc/ansible/hosts) entry containing details of your Windows Machine:

```
[win]
192.168.0.104   # IP Address of your Windows Machine

[win:vars]

ansible_user=ansible-user  # Windows User Name
ansible_password=ansible@123  # Windows User password
ansible_port=5986 # HTTPS port
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore # For now, we ignore the certs
```

Fire an adhoc command to check connectivity with Windows Host

```
ansible win -m win_ping
```

You are all set to control your Windows Machine Now!! <br>

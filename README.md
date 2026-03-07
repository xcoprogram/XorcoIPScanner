# Portable Windows Network Scanner

A lightweight, zero-dependency, single-file portable GUI network scanner for Windows. This utility is built using C# WinForms and targetting the native .NET Framework 4.x installed on all modern Windows machines.

## Features
- **Network Interface Selection**: Automatically detects active Ethernet, Wi-Fi, and VPN adapters.
- **Fast Ping Sweep**: Uses asynchronous parallel processing to scan entire subnets quickly.
- **MAC Address Resolution**: Uses ARP (iphlpapi.dll) to resolve hardware addresses for local devices (even if they block ICMP pings).
- **Hostname Resolution**: Resolves DNS hostnames for found devices.
- **Port Scanning**: Automatically checks for open web (80, 443), SSH (22), and RDP (3389) ports.
- **Sortable List**: Click any column header (IP, MAC, Hostname, etc.) to sort results.
- **Quick Action Context Menu**: Right-click any device to:
  - Open in Browser (HTTP/HTTPS)
  - Launch SSH session (via cmd/ssh)
  - Launch Remote Desktop (MSTSC)

## Recompilation
If you make changes to `NetworkScanner.cs`, you can recompile it into a standalone executable using the built-in Windows C# compiler (`csc.exe`). 

Run the following command in PowerShell or Command Prompt from this directory:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /out:NetworkScanner.exe NetworkScanner.cs
```

## Requirements
- Windows OS
- .NET Framework 4.5 or higher (pre-installed on Windows 10/11)

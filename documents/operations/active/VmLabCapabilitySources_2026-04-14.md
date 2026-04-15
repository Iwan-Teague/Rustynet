# VM Lab Capability Sources

**Status:** Active reference document

## Purpose

This document collects source-backed platform facts that are relevant to the
VM lab capability-reporting work. It is intentionally separate from the
Rustynet implementation truth documents so we do not mix "the OS can do this"
with "Rustynet currently supports this wrapper path".

## Source-Backed Platform Facts

### Windows SSH and OpenSSH

Microsoft documents that OpenSSH for Windows is available as a feature on
demand beginning with Windows 10 build 1809 and Windows Server 2019. The same
documentation family covers Windows Server 2025, Windows Server 2022, Windows
Server 2019, Windows 11, and Windows 10 as supported targets for the OpenSSH
packaging model.

Source:

- [OpenSSH for Windows overview](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview)
- [Can't install OpenSSH features](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/cant-install-openssh-features)
- [Upgrade in-box OpenSSH to the latest OpenSSH release](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/upgrade-in-box-openssh-to-latest-openssh-release)

### PowerShell Remoting Over SSH

Microsoft documents that PowerShell remoting over SSH is supported on Windows,
Linux, and macOS. The same documentation also states that SSH remoting does not
currently support endpoint configuration and Just Enough Administration (JEA)
in the same way that WSMan/WinRM remoting does.

Sources:

- [PowerShell remoting over SSH](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.5)
- [What is PowerShell?](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.6)

### macOS Remote Login

Apple documents that macOS Remote Login lets a remote computer access a Mac
using SSH or SFTP after the feature is enabled in Sharing settings.

Source:

- [Allow a remote computer to access your Mac](https://support.apple.com/guide/mac-help/mchlp1066/mac)

## How This Should Be Used

- Use these source-backed platform facts when writing capability-reporting
  docs.
- Do not infer Rustynet wrapper support from OS capability alone.
- Keep the current wrapper support truth and the source-backed platform facts
  separate.
- When a wrapper is still Linux-shell-based, say that explicitly even if the
  target OS has SSH or PowerShell remoting support.

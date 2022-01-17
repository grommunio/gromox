#
# A PowerShell migration script for Exchange.
#
# Copyright 2022 grommunio GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
# Authors: grommunio <dev@grommunio.com>
#          Walter Hofstaedtler <walter@hofstaedtler.com>
#
# Notice:
#
# This script assumes a correct setup with grommunio attached to the LDAP/AD.
# Script is compatible beginning with Windows Server 2012R2 and PowerShell 2.0.
#
# Instructions:
#
# 1. The mailboxes that will be migrated should already exist on the grommunio
#    side or should be automatically created by the parameter $CreateGrommunioMailbox.
#
# 2. Plink.exe must be located in the same directory as the script (latest
#    version available at
#    https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe).
#
# 3. The shared folder must be available from Windows and Linux (mount.cifs)
#    and have enough space for all .pst files. To conserve disk space, delete
#    the .pst file after each import by setting $DeletePST = $true.
#
# 4. Test the SSH login for plink.exe that it accepts the host key.
#
# 5. Fill in the variables.
#
# 6. Launch the script from an Exchange Admin shell.
#
# 7. Test.
#
# You may see this error:
#
# 	New-MailboxExportRequest : The term 'New-MailboxExportRequest' is not
# 	recognized as the name of a cmdlet, function, script file, or operable
# 	program.
#
# Resolution:
#
# * Add the Administrator to the -Role "Mailbox Import Export"
# * New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "Administrator" | ft -AutoSize
# * After migration, you can reset the membership
# * Remove-RoleGroupMember "Exchange Mailbox Import Export" -Member Administrator
#
# To mount the Windows share on Linux:
#
# 1. install the cifs-utils package
#    SUSE: `zypper in -y cifs-utils`
#    Debian / Ubuntu: `apt install cifs-utils`
#    EL: `yum install cifs-utils`
#
# 2. Create the mount point <shared folder name> in /mnt.
#    mkdir /mnt/<shared folder name>
#
# 3. Mount the Windows share. This needs the Windows user and password.
#    # mount.cifs "//<SERVER FQDN>/<shared folder name>" /mnt/<shared folder name>
#      -v -o ro,username=<Windows user>,password=<Windows password>
#
# To automount the Windows share, set $AutoMount = $true.


# Variables to be set by the user of this script
#
$GrommunioServer = "grommunio.example.com"

# Shared folder for .pst files on Windows
# The Exchange subsystem needs write rights to this directory.
$WinSharedFolder = "\\<server FQDN>\<shared folder name>"

# Shared folder for .pst files on Linux - the mount point
$LinuxSharedFolder = "/mnt/<shared folder name>"

# Login for the grommunio side shell
$LinuxUser = "root"

# The $LinuxUser password - or use certificate based authentication
$LinuxUserPWD = "Secret_root_Password"

# Ignore these mailboxes, an array of mail addresses
[string] $IgnoreMboxes = 'test1@example.com','test2@example.com'

# Delete .pst files after import to save space.
$DeletePST = $true

# Wait after each mailbox import and allow exiting.
$WaitAfterImport = $true

# Only needed if the script should automount the Windows share on Linux.
# Make sure that the cifs-utils package is installed.
$AutoMount = $true

# Windows user name. Make sure the Windows user exists and has at least read
# permissions on $WinSharedFolder.
$WindowsUser = "<Windows user>"

# Password for $WindowsUser. The password must not contain the characters "$"
# or "!", both of which cause problems in the Linux shell.
$WindowsPassword = "<Windows user password>"

# Create the grommunio mailbox
# LDAP must be configured and also be working. Do test LDAP before import.
$CreateGrommunioMailbox = $true

# From here on, no code or variables need changing by the user of this script.



# Mount the Windows shared folder via CIFS
#
function Linux-mount
{
	if ($AutoMount) {
		Write-Host "mkdir -p $LinuxSharedFolder" -fore green
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "mkdir -p $LinuxSharedFolder"
		$WinFolder = $WinSharedFolder.replace('\','/')
		Write-Host "mount.cifs $LinuxSharedFolder" -fore green
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "mount.cifs -v '$WinFolder' '$LinuxSharedFolder' -o user='$WindowsUser',password='$WindowsPassword',ro"
		Write-Host ""
	}
}

# Unmount the Windows shared folder
#
function Linux-umount
{
	if ($AutoMount) {
		Write-Host "umount $LinuxSharedFolder" -fore green
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "umount $LinuxSharedFolder"
		Write-Host ""
	}
}

# Test if plink.exe exists in $PSScriptRoot
#
function Test-Plink
{
	Write-Host ""
	# does plink.exe exist?
	if (!(Test-Path -Path $PSScriptRoot\plink.exe)) {
		Write-Host "Error: plink.exe not found, need plink.exe in $PSScriptRoot." -fore red
		exit 1
	}
}

# Test if the Exchange cmdlets are loaded
#
function Test-Exchange
{
	$Exchange_Cmdlets = $false
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue) {
		# Exchange 2007 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction SilentlyContinue) {
		# Exchange 2010 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (Get-PSSnapin -Registered Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue) {
		# Exchange 2013, 2016, 2019 cmdlets are loaded
		$Exchange_Cmdlets = $true
	}
	if (!$Exchange_Cmdlets) {
		Write-Host "Error: the Exchange cmdlets are not loaded. Launch this script from an Exchange Admin shell." -fore red
		exit 1
	}
}

# Check for prerequisites
#
Write-Host ""
Write-Host ""
Write-Host "***** Exchange to grommunio Migration *****" -fore green

# This construct works only in main. PS v2.0 does not provide $PSScriptRoot.
#
if (!$PSScriptRoot) {
	$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

Test-Plink
Test-Exchange
Linux-mount

# Statistics
#
$MailboxesMigrated = 0
$MailboxesSkipped = 0
$MailboxesCreated = 0
$MailboxesFailed = 0
$ImportErrors = 0
$ImportErrorsMBX = ""

# If we get a create error, do not import the mailbox.
#
$SkipImportCreateError = $false

#
# The migration loop
#
foreach ($Mailbox in (Get-Mailbox)) {
	$MigMBox = $Mailbox.PrimarySmtpAddress.ToString()
	if ($IgnoreMboxes.contains($MigMBox)) {
		$MailboxesSkipped++
		Write-Host "Ignoring mailbox: $MigMBox" -fore yellow
		continue
	}
	Write-Host ""
	# Clean up before exporting a mailbox
	# Remove all MailboxExportRequest, to make check for "Completed" more robust

	Write-Host "Removing all MailboxExportRequests." -fore green
	Get-MailboxExportRequest | Remove-MailboxExportRequest -Confirm:$false

	# Remove old / orphaned .pst file
	if (Test-Path -Path $WinSharedFolder\$MigMBox.pst) {
		Remove-Item -ErrorAction SilentlyContinue -Path $WinSharedFolder\$MigMBox.pst
		Write-Host "Removing outdated $MigMBox.pst file." -fore yellow
	}
	Write-Host ""

	# Create a .pst file for every mailbox found on system.
	#
	Write-Host "Exporting mailbox $MigMBox to file $MigMBox.pst..." -fore green

	# -Mailbox
	#
	# The Mailbox parameter specifies the source mailbox where the
	# contents are being exported from.
	#
	# In Exchange 2016 CU7 or later, this parameter is the type
	# MailboxLocationIdParameter, so the easiest value that you can
	# use to identify the mailbox is the Alias value.
	#
	# In Exchange 2016 CU6 or earlier, this parameter is the type
	# MailboxOrMailUserIdParameter, so you can use any value that
	# uniquely identifies the mailbox.
	#
	# https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps
	#
	New-MailboxExportRequest -Mailbox $Mailbox -FilePath $WinSharedFolder\$MigMBox.pst | ft -HideTableHeaders
	Write-Host -NoNewline "[Wait] " -fore yellow

	# Wait until the .pst file is created.
	# We probably should include a timeout to detect hanging exports.
	$nTimeout = 0
	while ((Get-MailboxExportRequest -Mailbox $Mailbox).Status -ne "Completed") {
		Start-Sleep -s 2
		$nTimeout += 2
		if ($nTimeout % 60 -eq 0) {
			Write-Host -NoNewline "|" -fore yellow
		} else {
			if ($nTimeout % 10 -eq 0) {
				Write-Host -NoNewline "." -fore yellow
			}
		}
	}

	Write-Host ""
	Write-Host "Export of mailbox $MigMBox took $nTimeout seconds." -fore green

	if (Test-Path $WinSharedFolder\$MigMBox.pst) {
		if ((Get-Item $WinSharedFolder\$MigMBox.pst).length -gt 0mb) {
			$size = [math]::ceiling($(Get-Item $WinSharedFolder\$MigMBox.pst).length/(1024*1024))
			Write-Host "Size of $MigMBox.pst is $size MB" -fore green
			$MailboxesMB += $size
		}
	}

	Write-Host ""

	# Wait for release of $WinSharedFolder\$MigMBox.pst
	Start-Sleep -s 10

	# If requested, create the grommunio mailbox
	if ($CreateGrommunioMailbox) {
		Write-Host "Create grommunio mailbox: $MigMBox." -fore green
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "grommunio-admin ldap downsync -a $MigMBox"
		if ($lastexitcode -eq 0) {
			Write-Host "Mailbox: $MigMBox created successfully." -fore green
			$MailboxesCreated++
		} else {
			Write-Host "Creation of mailbox: $MigMBox failed." -fore red
			$MailboxesFailed++
			$SkipImportCreateError = $true
		}
	}

	if (!$SkipImportCreateError) {
		Write-Host ""
		$ImportStartDate=(GET-DATE)

		# Using plink, start importing this mailbox and .pst
		# file on the grommunio host.
		Write-Host "Starting import of mailbox: $MigMBox in grommunio." -fore green
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "gromox-pff2mt -s $LinuxSharedFolder/$MigMBox.pst | gromox-mt2exm -u $MigMBox; if test \`${PIPESTATUS[0]} != 0 || test \`${PIPESTATUS[1]} != 0; then false; fi"
		if ($lastexitcode -eq 0) {
			Write-Host "Import of mailbox: $MigMBox done." -fore green
			$MailboxesMigrated++
		} else {
			Write-Host "Mailbox: $MigMBox imported with errors." -fore red
			$ImportErrors++
			$ImportErrorsMBX += $MigMBox + ", "
			# Wait for admin to make a decision
			$WaitAfterImport = $true
		}
		# Show import time in seconds
		$ImportEndDate=(GET-DATE)
		$Duration = [math]::ceiling($(NEW-TIMESPAN -Start $ImportStartDate -End $ImportEndDate).TotalSeconds)
		Write-Host "Import of mailbox $MigMBox took $Duration seconds." -fore green
	}

	# Try to import the next mailbox.
	$SkipImportCreateError = $false

	if ($DeletePST) {
		Write-Host "Remove the imported .pst file: $WinSharedFolder\$MigMBox.pst to save disk space." -fore green
		if (Test-Path -Path $WinSharedFolder\$MigMBox.pst) {
			Remove-Item -ErrorAction SilentlyContinue -Path $WinSharedFolder\$MigMBox.pst
		} else {
			Write-Host "Error .pst file: $WinSharedFolder\$MigMBox.pst not found." -fore red
		}
	}

	Write-Host ""
	Write-Host "Status: $MailboxesMigrated mailboxes processed, $MailboxesSkipped mailboxes skipped, ($ImportErrors imports failed)" -fore yellow
	Write-Host ""

	if (!$WaitAfterImport) {
		continue
	}
	Write-Host ""
	$decision = "Y"
	$OK = $false
	while (!$OK) {
		$decision = $(Write-Host "Are you sure you want to proceed with next mailbox [Y]es [A]bort [C]ontinue? " -fore yellow -NoNewLine; Read-Host)
		$decision = $decision.ToUpper()
		switch ($decision) {
		"Y" {
			Write-Host "Import next mailbox" -fore green
			$OK = $true
		}
		"A" {
			Write-Host "Exit on admin request." -fore red
			$OK = $true
		}
		"C" {
			Write-Host "Continue without" -fore green
			$WaitAfterImport = $false
			$OK = $true
		}
		}
	}
	if ($decision -eq "A") {
		break
	}
}

Linux-umount

# Remove all "Completed" MailboxExportRequests
#
Get-MailboxExportRequest | where {$_.status -eq "Completed"} | Remove-MailboxExportRequest -Confirm:$false

# Print summary
#
Write-Host ""
Write-Host "Total of $MailboxesMigrated mailboxes migrated, $MailboxesSkipped mailboxes skipped." -fore green
if ($CreateGrommunioMailbox) {
	Write-Host "$MailboxesCreated mailboxes created, $MailboxesFailed mailboxes skipped." -fore green
}
if ($ImportErrors -ne 0) {
	Write-Host "$ImportErrors mailboxes imported with errors." -fore red
	Write-Host "Affected mailboxes: $ImportErrorsMBX" -fore red
}
Write-host "Imported a total of $MailboxesMB MB of mailbox data." -fore green
Write-Host ""
Write-Host "Remove orphaned .pst files from $WinSharedFolder." -fore green
Write-Host "Finished import." -fore green
Write-Host ""

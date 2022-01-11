#
# A PowerShell migration script from Exchange.
#
# Instructions:
#
# 1. The mailboxes that will be migrated must exist on the grommunio side.
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
#
# To mount the Windows share on Linux:
#
# 1. install the cifs-utils package
#    SUSE: `zypper in -y cifs-utils`
#    Debian: `apt install cifs-utils`
#
# 2. Create the mount point <shared folder name> in /mnt.
#    mkdir /mnt/<shared folder name>
#
# 3. Mount the Windows share. This needs the Windows user and password.
#    # mount.cifs "//<SERVER FQDN>/<shared folder name>" /mnt/<shared folder name>
#      -v -o ro,username=<Windows user>,password=<Windows password>
#
# To automount the Windows share, set $AutoMount = $true.


# Variables to be set by the user
#
$GrommunioServer = "grommunio.example.com"

# Shared folder for .pst files on Windows
# The Exchange subsystem needs write rights to this directory.
$WinSharedFolder = "\\<server FQDN>\<shared folder name>"

# Shared folder for .pst files on Linux - the mount point
$LinuxSharedFolder = "/mnt/<shared folder name>"

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

# From here on, no code or variables need changing by the user.



# cifs_mount the Windows shared folder
#
function Linux-mount
{
	if ($AutoMount) {
		Write-Host "mkdir -p $LinuxSharedFolder"
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "mkdir -p $LinuxSharedFolder"
		$WinFolder = $WinSharedFolder.replace('\','/')
		Write-Host "mount.cifs $LinuxSharedFolder"
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "mount.cifs -v '$WinFolder' '$LinuxSharedFolder' -o user='$WindowsUser',password='$WindowsPassword',ro"
		Write-Host ""
	}
}

# Unmount the Windows shared folder
#
function Linux-umount
{
	if ($AutoMount) {
		Write-Host "umount $LinuxSharedFolder"
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
		Write-Host "Error: the Exchange cmdlets are not loaded. Please launch this script from an Exchange Admin shell." -fore red
		exit 1
	}
}

# Check for prerequisites
#
Write-Host ""

# This construct works only in main. PS v2.0 does not provide $PSScriptRoot.
#
if (!$PSScriptRoot) {
	$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

Test-Plink
Test-Exchange
Linux-mount

# statistics
$MailboxesMigrated = 0
$MailboxesSkipped = 0
$MailboxesCreated = 0
$MailboxesFailed = 0

# If we cannot create the mailbox, do not import.
#
$SkipImportCreateError = $false

#
# The migration loop
#
$ErrorInLoop = 0
foreach ($Mailbox in (Get-Mailbox)) {
	Write-Host ""
	$MigMBox = $Mailbox.PrimarySmtpAddress.ToString()
	#
	if ($IgnoreMboxes.contains($MigMBox)) {
		$MailboxesSkipped++
		Write-Host "Ignoring mailbox: $MigMBox" -fore yellow
		continue
	}

	# Create a .pst file for every mailbox found on system.
	#
	Write-Host "Export $MigMBox.pst file, be patient."

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
	New-MailboxExportRequest -Mailbox $Mailbox -FilePath $WinSharedFolder\$MigMBox.pst

	# Wait until the .pst file is created.
	# We probably should include a timeout to detect hanging exports.
	$nTimeout = 0
	while ((Get-MailboxExportRequest -Mailbox $Mailbox).Status -ne "Completed") {
		Start-Sleep -s 2
		$nTimeout += 2
		if ($nTimeout % 10 -eq 0) {
			# Entertain the admin, print one dot every 10 seconds
			Write-Host -NoNewline "."
		}
	}
	Write-Host "Export of mailbox $MigMBox took $nTimeout seconds"

	# If requested, create the grommunio mailbox.
	if ($CreateGrommunioMailbox) {
		Write-Host "Create grommunio mailbox: $MigMBox."
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "grommunio-admin ldap downsync -a $MigMBox"
		if ($lastexitcode -eq 0) {
			Write-Host "Mailbox: $MigMBox created successfully."
			$MailboxesCreated++
		} else {
			Write-Host "Creation of mailbox: $MigMBox failed." -fore red
			$MailboxesFailed++
			$SkipImportCreateError = $true
		}
	}

	if (!$SkipImportCreateError) {
		# Using plink, start importing this mailbox and .pst
		# file on the grommunio host.
		Write-Host "Starting import of mailbox: $MigMBox in grommunio."
		.\plink.exe -ssh -batch $LinuxUser@$GrommunioServer -pw $LinuxUserPWD "gromox-pffimport -s $MigMBox $LinuxSharedFolder/$MigMBox.pst | gromox-mt2exm -u $MigMBox"
		$MailboxesMigrated++
		Write-Host "Import of mailbox: $MigMBox done."
	}

	# Try to import the next mailbox.
	$SkipImportCreateError = $false

	if ($DeletePST) {
		Write-Host "Remove the imported .pst file: $WinSharedFolder\$MigMBox.pst to save disk space."
		if (Test-Path -Path $WinSharedFolder\$MigMBox.pst) {
			Remove-Item -Confirm $false -ErrorAction SilentlyContinue $WinSharedFolder\$MigMBox.pst
		} else {
			 Write-Host "Error .pst file: $WinSharedFolder\$MigMBox.pst not found." -fore red
		}
	}

	if (!$WaitAfterImport) {
		continue
	}

	Write-Host ""
	# This dialog works with PowerShell 2.0 and newer
	$decision = "Y"
	$OK = $false
	while (!$OK) {
		$decision = Read-Host "Are you sure you want to proceed with next mailbox [Y]es [A]bort [C]ontinue?"
		$decision = $decision.ToUpper()
		switch ($decision) {
		"Y" {
			Write-Host "Import next mailbox" -fore Green
			$OK = $true
		}
		"A" {
			Write-Host "Exit on admin request." -fore red
			$OK = $true
		} # exit foreach loop outside while loop!
		"C" {
			Write-Host "Continue without" -fore Green
			$WaitAfterImport = $false
			$OK = $true
		}
		}
	}
	if ($decision = "A") {
		$ErrorInLoop++
		break
	}
}

Linux-umount
Write-Host ""
Write-Host "Total of $MailboxesMigrated mailboxes migrated, $MailboxesSkipped mailboxes skipped."
if ($CreateGrommunioMailbox) {
	Write-Host "$MailboxesCreated mailboxes created, $MailboxesFailed mailboxes skipped."
}
Write-Host ""
Write-Host "Remove the .pst files from $WinSharedFolder."
Write-Host "Import finished."
Write-Host ""

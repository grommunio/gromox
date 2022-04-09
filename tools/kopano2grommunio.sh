#!/bin/bash
#
# A Shell migration script for Kopano.
#
# Copyright 2022 grommunio GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
# Authors: grommunio <dev@grommunio.com>
#          Walter Hofstaedtler <walter@hofstaedtler.com>
#
# Notice:
#
# This script assumes a correct setup with grommunio attached to the LDAP/AD.
# Script is compatible with any linux target source.
#
# Instructions:
#
# 1. The mailboxes that will be migrated should already exist on the grommunio
#    side or should be automatically created by the parameter CreateGrommunioMailbox=1.
#
# 2. This script needs an ssh login to mount the Kopano attachment store on grommunio
#    Password and key-based logins are supported
#
# 2.1. install sshfs on grommunio server
#      grommunio Appliance / SUSE: zypper in sshfs
#      Debian / Ubuntu: apt-get install sshfs
#
# 2.2. verify fuse kernel driver is available
#      ls -l /dev/fuse
#
# 2.3. create mount directory
#      mkdir -p /mnt/kopano/
#
# 3. The migration tool needs a MySQL connection to the Kopano server
#    Create Maria DB migration user on Kopano server
#    KopanoMySqlUser  - this user loges in from grommunio server
#    KopanoMySqlPWD   - password for KopanoMySqlUser
#    GrommunioAddr    - IP address of grommunio server
#
#    This have to be done on Kopano server:
#    	mysql -u root -p
#
#    Create user:
#    	CREATE USER '<KopanoMySqlUser>'@'<GrommunioAddr>' IDENTIFIED BY '<KopanoMySqlPWD>';
#
#    Grant read only access to database kopano or zarafa:
#    	GRANT SELECT ON kopano.* TO '<KopanoMySqlUser>'@'<GrommunioAddr>';
#
#    Save and exit:
#    	FLUSH PRIVILEGES;
#    	quit;
#
#    Note: If the database is named zarafa, the migration supports migrations of the databases
#          with ZCP version 7.1+ (schema version 61)
#          Validation is possible by checking the versions table: SELECT * FROM versions;
#
#    Change bind-address = <Kopano_Server_Addr> and restart MariaDB
#    the bind-address is a config directive in the MySQL config file and
#    looks like this:
#
#    	bind-address = 192.168.130.2
#
#    Test from grommunio server:
#
#    	mysql -h <KopanoServer> -u <KopanoMySqlUser> -p
#
# 4. Provide a text file that lists the grommunio mail addresses and the Kopano login, separated by colons,
#    every line is one mailbox to migrate. lines starting with # are remarks/comments and not evaluated
#    A sample file can be created when setting: CreateSampleMigrationList=1
#    Sample file:
#
#    # sample user file for Kopano 2 grommunio migration
#    # mail address,Kopano login name|store GUID,' '|0|1
#    # Import the Public Store
#    @domain.com,<Public Store GUID>
#    # Import user with mail address, type:0
#    user1@domain.com,user1,0
#    user2@domain.com,user2,0
#    # Import user but specify the Kopano store GUID instead of Kopano login, type:1
#    user3@domain.com,<User 3 store GUID>,1
#
#    How to find the Public Store GUID?
#    On the Kopano server version 8.7 or newer execute this command:
#
#    	kopano-storeadm -M | grep -A 1 'Public Folders'
#
#    Get the GUID and populate the text file.
#    For Kopano versions 8.6 and older, you need a MySQL query to read the Public Store GUID
#    Log on to the MySQL database and select the kopano or zarafa database.
#
#    	mysql -u root -p
#    	use kopano;
#    	select hex(guid),user_name from stores;
#
#    The GUID for Everyone is the Public Store GUID.
#
#    In some rare cases, the migration tool cannot find a Kopano store for a given login name,
#    in this case, we need to specify the Kopano Store GIUD for this user.
#    This issue may occur if the store have been renamed a few times.
#
#    How to find the Kopano Store GUID?
#    On the Kopano Server execute this command:
#
#    	kopano-admin --details <Kopano Login Name>
#
#    Get the GUID and populate the text file.
#    In the migration text file, mark the GIUD with type:1 after the GUID like:
#    user3@domain.com,<User 3 store GUID>,1
#
# 5. Define the variables.
#
# 6. Test the migration
#
# 7. If you delete all mailboxes and Public Store on grommunio,
#    restart the grommunio server or its services before starting the migration to clear all caches


# Variables to be set by the user of this script
#
KopanoServer="kopanodb.example.com"

# Login for the Kopano server
KopanoUser="root"

# The KopanoUser password, leave empty to use certificate based authentication
KopanoUserPWD="Secret_root_Password"
KopanoUserPWD=""

# Path on Kopano server to the Kopano attachment store
KopanoAttachments="/srv/kopano/attachments/"

# Path on grommunio server where the Kopano attachments are mounted
GrommunioMount="/mnt/kopano/"

# MYSQL user for Kopano database
KopanoMySqlUser="GrommunioUser"

# Passwort for MYSQL user for Kopano database
KopanoMySqlPWD="Secret_mysql_Password"
KopanoMySqlPWD=""

# The Kopano MySQL database, usually "kopano" but on older installations "zarafa"
#KopanoDB="zarafa"
KopanoDB="kopano"

# The migration list containing the grommunio mailbox names and the Kopano login names or store IDs
MigrationList="/tmp/k2g_list.txt"

# Create a sample $MigrationList file, an existing $MigrationList will not be overwritten
# For normal migration set this variable to 0
CreateSampleMigrationList=0

# Create the grommunio mailbox before import, 1=yes, 0=no
# This only works with an LDAP user source
CreateGrommunioMailbox=1

# Create only the mailboxes, but do not import data, 1=yes, 0=no
# This sets CreateGrommunioMailbox=1
OnlyCreateGrommunioMailbox=0

# Wait after each mailbox import and allow exiting, 1=wait, 0=continue
WaitAfterImport=0

# Stops the script if a mailbox creation or import error occurs, 1=stop, 0=continue
# For unattended import WaitAfterImport=0 and StopOnError=0 must be set.
StopOnError=1

# The language with which all mailboxes are created.
# The languages can be found in: /usr/share/grommunio-admin-api/res/storelangs.json
MailboxLanguage="de_DE"

# Migration log file
LOG=/tmp/kopano2grommunio.log

# From here on, no code or variables need changing by the user of this script.
#
# Trap function for Clean Up
finish () {
	# Your cleanup code here
	echo "$(tput setaf 7)Kill ssh-agent in ERROR TRAP!$(tput sgr 0)"
	# kill the ssh-agent and unset variables
	ssh-agent -k > /dev/null
	sleep 2
	unset SSH_AGENT_PID
	unset SSH_AUTH_SOCK
	# killall ssh-agent
	#
	# umount the attachment directory
	if [[ -d $GrommunioMount/0 ]]; then
		$FUSERMOUNT -u $GrommunioMount | tee -a $LOG
	fi
	#
	#echo "$(tput setaf 2)End of script.$(tput sgr 0)"
}
trap finish EXIT

# Write to log and screen
Write-MLog () {
	LEVEL="???"
	# prepare color and severity level
	case $2 in
		"red")
		LEVEL="FAIL"
		COL=1
		;;
		"green")
		LEVEL="INFO"
		COL=2
		;;
		"yellow")
		LEVEL="WARN"
		COL=3
		;;
		"cyan")
		LEVEL="INFO"
		COL=6
		;;
		"white")
		LEVEL="	"
		COL=7
		;;
		"none")
		LEVEL=""
		COL=7
		;;
		*)
		LEVEL="UNKN"
		COL=5
	esac
	[[ $2 != "none" ]] && echo "$(tput setaf $COL)$1 $(tput sgr 0)"
	echo "$(date +"%d.%m.%Y %H:%M:%S") $LEVEL $1">>$LOG
}

# Main migration logic

# find required commands
SSHFS="$(which sshfs)"
FUSERMOUNT="$(which fusermount)"
#
for File in $SSHFS $FUSERMOUNT;
do
	if [[ ! -e $File ]]; then
		WriteLogCon 1 "Error: command $File not found, aborting."
		exit 1 # terminate and indicate error
	fi
done

# create sample migration list file
if [[ $CreateSampleMigrationList -eq 1 ]]; then
	if [[ -f "$MigrationList" ]]; then
		echo "The file $MigrationList exists, we will *not* overwrite $MigrationList."
		echo "Please rename or remove $MigrationList and try again."
		exit 1
	fi
	# sample content
	{
		echo "# Sample user list for Kopano 2 grommunio migration"
		echo "# mail address,Kopano login name|store GUID,' '|0|1"
		echo "# "
		echo "# Import the Public Store"
		echo "@domain.com,<Public Store GUID>"
		echo "# "
		echo "# Import users with mail address and Kopano login name, type:0"
		echo "user1@domain.com,user1,0"
		echo "user2@domain.com,user2,0"
		echo "# "
		echo "# Import a user but specify the Kopano store GUID instead of Kopano login, type:1"
		echo "user3@domain.com,<User 3 store GUID>,1"
	} > $MigrationList

	echo "Sample $MigrationList have been created."
	echo "Populate the mail addresses, login names and types."
	echo "Last, set \$CreateSampleMigrationList=0 and start the migration."
	echo ""
	#echo "sed -i s/^CreateSampleMigrationList=1/CreateSampleMigrationList=0/ $0"
	sed -i "s/^CreateSampleMigrationList=1/CreateSampleMigrationList=0/" "$0"
	echo ""
	exit 0
fi

# Statistics:
MailboxesTotal=0
#MailboxesSkipped=0
MailboxesCreated=0
MailboxesCreateFailed=0
MailboxesImported=0
MailboxesImportFailed=0
CreateErrorsMBX=""
ImportErrorsMBX=""

Write-MLog "" "white"
Write-MLog "" "white"
Write-MLog "===========================================================================" "none"
Write-MLog "" "white"
Write-MLog "" "white"
Write-MLog "Kopano 2 grommunio migration start" "cyan"

#Write-MLog "MSG red	" "red"
#Write-MLog "MSG yellow " "yellow"
#Write-MLog "MSG green  " "green"
#Write-MLog "MSG cyan   " "cyan"
#Write-MLog "MSG white  " "white"
#Write-MLog "MSG unknown" "unkn"

# create mount directory if not exists
if [[ ! -d "$GrommunioMount" ]]; then
	mkdir -p $GrommunioMount | tee -a $LOG
	Write-MLog "Create mount directory $GrommunioMount" "white"
	Write-MLog "" white
fi

Write-MLog "Mount attachment directory: $GrommunioMount" "yellow"
# mount the attachment directory
if [[ -z "$KopanoUserPWD" ]]; then
	# certificate login
	Write-MLog "Please Enter Public Server Key Pass Phrase in next Line" "yellow"
	# read -sp 'Pass Phrase:' PASS_PHRASE
	ssh-agent -k > /dev/null
	sleep 2
	#unset SSH_AGENT_PID | tee -a $LOG
	#unset SSH_AUTH_SOCK | tee -a $LOG
	#
	ssh-add
	$SSHFS $KopanoUser@$KopanoServer:$KopanoAttachments $GrommunioMount -o idmap=user | tee -a $LOG
	ExitCode=$?
	Write-MLog "" white
else
	# password login
	$SSHFS $KopanoUser@$KopanoServer:$KopanoAttachments $GrommunioMount -o idmap=user,password_stdin <<< "$KopanoUserPWD" | tee -a $LOG
	ExitCode=$?
	Write-MLog "" white
fi

# test for Kopano attachment store, 10 directories 0..9 must exist, we look for 3 directories
if [[ ! -d $GrommunioMount/0 ]] || [[ ! -d $GrommunioMount/5 ]] || [[ ! -d $GrommunioMount/9 ]]; then
	echo "$KopanoAttachments resp. $GrommunioMount does not exist. Please check readme on how to setup $0"
	exit 1 # terminate and indicate error
fi


if [[ $OnlyCreateGrommunioMailbox -eq 1 ]]; then
	Write-MLog "Only create mailboxes but do not import data." "yellow"
	CreateGrommunioMailbox=1
fi

Write-MLog "" "white"
#
# $MigMBox	- is the grommunio mailbox
# $KopanoUser - the Kopano login name
# $IsID	   - Mail address = 0, Kopano store GUID = 1
# now we need to extract $MigMBox,$KopanoUser,$IsID from $MigrationList

# we need the command "exec {stdin}<&0" to read from keyboard / stdin
exec {stdin}<&0
while IFS= read -r line; do
	# Write-MLog "Read from file: $line" "white"
	line=${line//[[:blank:]]/}
	# Ignore comment lines
	[[ $line =~ ^#.* ]] && continue
	# if we do not find a mail address, read next line
	[[ $line != *"@"* ]] && continue
	IFS=, read -r MigMBox KopanoUser IsID <<< "$line"

	# if empty, populate IsID with default value
	[[ -z $IsID ]] && IsID=0

	Write-MLog "" "white"
	Write-MLog "We found mailbox: $MigMBox and Kopano user/GUID: $KopanoUser, ID: $IsID" "green"

	MailboxesTotal=$((MailboxesTotal+1))
	SkipImportCreateError=0

	if [[ $MigMBox =~ ^@.* ]]; then
		Write-MLog "This is the Kopano public store, do not create a mailbox for: $MigMBox" "yellow"
	else
		if [[ $CreateGrommunioMailbox -eq 1 ]]; then
			Write-MLog "Create mailbox: $MigMBox" "yellow"
			grommunio-admin ldap downsync -l $MailboxLanguage -a "$MigMBox" | tee -a $LOG
			ExitCode=$?
			if [[ $ExitCode -eq 0 ]]; then
				# OK
				MailboxesCreated=$((MailboxesCreated+1))
				Write-MLog "Mailbox: $MigMBox created successfully" "green"
			else
				# Failed
				MailboxesCreateFailed=$((MailboxesCreateFailed+1))
				CreateErrorsMBX+=" $MigMBox"
				SkipImportCreateError=1
				Write-MLog "Cannot create mailbox: $MigMBox, error $ExitCode" "red"
				# Wait for admin to make a decision.
				[[ $StopOnError -eq 1 ]] && WaitAfterImport=1
			fi
		fi
	fi
	#
	#
	if [[ $SkipImportCreateError -eq 0 ]] && [[ $OnlyCreateGrommunioMailbox -eq 0 ]]; then
		#
		if [[ $MigMBox =~ ^@.* ]]; then
			Write-MLog "This is the Kopano public store (GUID: $KopanoUser) for domain: $MigMBox" "yellow"
			(SRCPASS=$KopanoMySqlPWD gromox-kdb2mt -s --src-host $KopanoServer --src-user $KopanoMySqlUser --src-db $KopanoDB --src-guid "$KopanoUser" --src-at $GrommunioMount | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a $LOG
			ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
		else
			if [[ $IsID -eq 0 ]]; then
				Write-MLog "Migration of mailbox $MigMBox with Kopano login $KopanoUser start" "yellow"
				# add parameter -s to import into correct folders. eg: gromox-kdb2mt -s ....
				(SRCPASS=$KopanoMySqlPWD gromox-kdb2mt -s --src-host $KopanoServer --src-user $KopanoMySqlUser --src-db $KopanoDB --src-mbox "$KopanoUser" --src-at $GrommunioMount | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a $LOG
				ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
			else
				Write-MLog "Migration of mailbox $MigMBox with Kopano GUID $KopanoUser start" "yellow"
				# add parameter -s to import into correct folders. eg: gromox-kdb2mt -s ....
				(SRCPASS=$KopanoMySqlPWD gromox-kdb2mt -s --src-host $KopanoServer --src-user $KopanoMySqlUser --src-db $KopanoDB --src-guid "$KopanoUser" --src-at $GrommunioMount | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a $LOG
				ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
			fi
		fi
		if [[ $ExitCode -eq 0 ]]; then
			MailboxesImported=$((MailboxesImported+1))
			Write-MLog "Mailbox: $MigMBox imported successfully" "green"
		else
			MailboxesImportFailed=$((MailboxesImportFailed+1))
			ImportErrorsMBX+=" $MigMBox,"
			Write-MLog "Cannot create mailbox: $MigMBox, error $ExitCode" "red"
			[[ $StopOnError -eq 1 ]] && WaitAfterImport=1
		fi
	else
		# Try import of next mailbox
		SkipImportCreateError=0
		Write-MLog "Skipped mailbox: $MigMBox to do creation error" "red"
	fi
	Write-MLog "Migration of mailbox $MigMBox end" "yellow"

	Write-MLog "" "white"
	Write-MLog "Total of $MailboxesTotal mailboxes processed, $MailboxesCreated mailboxes created, $MailboxesImported mailboxes imported, " yellow
	Write-MLog "$MailboxesCreateFailed mailboxes creation failed, $MailboxesImportFailed imports failed." yellow
	Write-MLog "" "white"

	[[ $WaitAfterImport -eq 0 ]] && continue
	#
	decision="Y"
	OK=0
	while [[ $OK -eq 0 ]]
	do
		Write-MLog "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " "none"
		read -r -p "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " -n1 decision <&$stdin
		decision=${decision^^}
		echo ""; echo " $decision"
		case $decision in
			"Y")
			  Write-MLog "Import next mailbox" "green"
			  OK=1
			;;
			"A")
			  Write-MLog "Exit on Admin request." "red"
			  OK=1
			;;
			"C")
			  Write-MLog "Continue without future questions until errors" "green"
			  WaitAfterImport=0
			OK=1
			;;
		esac
	done
	[[ $decision == "A" ]] && break
done <"$MigrationList"

Write-MLog "" white
Write-MLog "Migration done, clean up" "cyan"

# Migration done, clean up
Write-MLog "Unmount attachment directory: $GrommunioMount" "yellow"
# Unmount the directory
$FUSERMOUNT -u $GrommunioMount | tee -a $LOG

# Print summary
Write-MLog "" white
Write-MLog "Total of $MailboxesTotal mailboxes processed" "green"

if [[ $CreateGrommunioMailbox -eq 1 ]]; then
	Write-MLog "$MailboxesCreated mailboxes created" "green"
	if [[ $MailboxesCreateFailed -ne 0 ]]; then
		Write-MLog "$MailboxesCreateFailed mailboxes creation failed" "red"
		Write-MLog "Affected mailboxes: $CreateErrorsMBX" "red"
	fi
fi
Write-MLog "$MailboxesImported mailboxes imported" "green"
if [[ $MailboxesImportFailed -ne 0 ]]; then
	Write-MLog "$MailboxesImportFailed mailboxes imported with errors or import failed" "red"
	Write-MLog "Affected mailboxes: $ImportErrorsMBX " "red"
fi

Write-MLog "Kopano 2 grommunio migration done." "cyan"

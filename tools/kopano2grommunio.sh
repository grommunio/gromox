#!/bin/bash
#
# A bash script for Kopano 2 grommunio migration.
#
# Copyright 2022-2024 Walter Hofstaedtler
# SPDX-License-Identifier: AGPL-3.0-or-later
# Authors: grommunio <dev@grommunio.com>
#          Walter Hofstaedtler <walter@hofstaedtler.com>
#
#
# Credits:
#
# Some changes in the documentation of crpb.
#
# Notice:
#
# * This script assumes a correct setup of grommunio attached to LDAP/AD.
# * Script is compatible with any Linux target source.
# * Importantly, this script was written for GNU bash and is not POSIX compliant.
# * Script requires at least Gromox 2.21.
#
#
# Instructions:
#
# 1. The mailboxes that will be migrated should already exist on the grommunio
#    side or should be automatically created by the parameter CreateGrommunioMailbox=1.
#
# 2. This script needs an SSH login to mount the Kopano attachment store on grommunio.
#    Password and key-based logins are supported.
#
# 2.1. Install sshfs on the grommunio server:
#      grommunio Appliance / SUSE: zypper in sshfs
#      Debian / Ubuntu: apt-get install sshfs
#
# 2.2. Verify that the FUSE kernel driver is available and loaded:
#      ls -l /dev/fuse
#
# 2.3. Create the mount directory:
#      mkdir -p /mnt/kopano/
#
# 3. The migration tool needs a MySQL connection to the Kopano database server.
#    Create a Maria DB migration user on Kopano database server.
#    KopanoMySqlServer - the database server, typically the same server as the Kopano server itself.
#    KopanoMySqlUser   - this user logs in from grommunio server.
#    KopanoMySqlPWD    - password for KopanoMySqlUser.
#    GrommunioIP       - IP address of grommunio server.
#
#    This has to be done on the Kopano database server:
#       mysql -u root -p
#
#    Create user:
#       CREATE USER '<KopanoMySqlUser>'@'<GrommunioAddr>' IDENTIFIED BY '<KopanoMySqlPWD>';
#
#    Grant read-only access to database kopano or zarafa:
#       GRANT SELECT ON kopano.* TO '<KopanoMySqlUser>'@'<GrommunioAddr>';
#
#    Save and exit:
#       FLUSH PRIVILEGES;
#       quit;
#
#    Note: If the database is named zarafa, the migration supports migrations of the databases
#          with ZCP version 7.1+ (schema version 61).
#          Validation is possible by checking the versions table: SELECT * FROM versions;
#
#    Change bind-address = <Kopano_Server_Addr> and restart MariaDB.
#    The bind-address is a config directive in the MySQL config file and
#    looks like this:
#
#       bind-address = 192.168.10.2
#
#    Test from the grommunio server:
#
#       mysql -h <KopanoMySqlServer> -u <KopanoMySqlUser> -p
#
# 4. Provide a text file that lists the grommunio mail addresses and the Kopano login.
#    We provide the script: "create_k2g_migration_lists.sh" to create the raw
#    migration list on the Kopano server. Configure and launch "create_k2g_migration_lists.sh"
#    on the Kopano server and transfer the created mailbox list to the grommunio server.
#
#    * You may sort the list on priority: High-priority users first, low-priority mailboxes last.
#    * Do you decide to migrate the Public Store as the first or last item?
#
#    Structure of the migration list: separated by colons, every line is one mailbox to migrate.
#    Lines starting with # are remarks/comments and not evaluated.
#    A sample file can be created whit setting: CreateSampleMigrationList=1.
#    Sample file:
#
#    # sample user file for Kopano 2 grommunio migration
#    # mail address,Kopano login name|store GUID,' '|0|1
#    # Migrate the Public Store
#    @domain.com,<Public Store GUID>
#    # Migrate user with mail address, type:0
#    user1@domain.com,user1,0
#    user2@domain.com,user2,0
#    # Migrate user but specify the Kopano store GUID instead of Kopano login, type:1
#    user3@domain.com,<User 3 store GUID>,1
#
#    How to find the Public Store GUID?
#    On the Kopano server (version 8.7 or newer), execute the command:
#
#       kopano-storeadm -M | grep -A 1 'Public Folders'
#
#    Get the GUID and populate the text file.
#    For Kopano versions 8.6 and older, you need a MySQL query to read the Public Store GUID.
#    Log on to the MySQL database and select the kopano or zarafa database.
#
#       mysql -u root -p
#       use kopano;
#       select hex(guid),user_name from stores;
#
#    The GUID for Everyone is the Public Store GUID.
#
#    Errors and quirks:
#    In some rare cases, the migration tool cannot find a Kopano store for a
#    given login name. In this case, we need to specify the Kopano Store GIUD
#    for this user. This issue may occur if the store have been renamed a few
#    times or unhooked and hooked onto another account.
#
#    How to find the Kopano Store GUID?
#    On the Kopano Server execute this command:
#
#       kopano-admin --details <Kopano Login Name>
#
#    Get the GUID and populate the text file.
#    In the migration text file, mark the GIUD with type:1 after the GUID like:
#
#	user3@domain.com,<User 3 store GUID>,1
#
#    A command to show all Kopano Store GUIDs as seen by the migration tool:
#       SQLPASS=<KopanoMySqlPWD> gromox-kdb2mt --sql-host <KopanoServer> --sql-port=3306 --sql-db=<KopanoDB> --sql-user=GrommunioUser --src-attach "" --mbox-mro "" 2>&1 | less -SX
#
#    Important:
#    * Verify that the store GUIDs match the store GUIDs found in the list created by create_k2g_migration_lists.sh.
#    * If the store GUIDs do *not* match, migrate this mailbox with the store GUID found with create_k2g_migration_lists.sh.
#    * A store GUID mismatch might happen if a Kopano store was unhooked and hooked onto another account or renamed.
#    * Note that this script can only create mailboxes if the source is an LDAP directory.
#    * Mailboxes that do not come from an LDAP directory must first be created manually in the Admin UI.
#
# 5. Create the Zarafa to MAPI mapping/ACL file on the Kopano server.
#    grommunio provides two scripts to map Zarafa addressing/ACLs to MAPI addressing:
#
#    1. "kdb-uidextract" for multi-server installations and
#    2. "kdb-uidextract-limited" for single server installations - we focus an this script.
#
#    Launch kdb-uidextract-limited on the Kopano server and transfer the mapping file to the grommunio server.
#    A sample command line how to launch kdb-uidextract-limited and create the mapping file:
#
#	./kdb-uidextract-limited > kdb-uidextract.map
#
#    Populate parameter KdbUidMap="/path/kdb-uidextract.map" with the copied mapping file.
#    Note that, if you need the script "kdb-uidextract", this will be a huge migration, so
#    consider to contact grommunio Professional Services and ask for help.
#
# 6. Set the variables - how should the migration proceed
#    Here, you have to decide if the mailboxes should be created by the script and when the mailboxes should be created.
#
#    If the mailboxes are already created or there is no LDAP source:
#      CreateGrommunioMailbox=0
#      OnlyCreateGrommunioMailbox=0
#    In this case, the script imports the Kopano data into existing mailboxes, mailbox by mailbox.
#
#    The mailboxes should be created during the migration process:
#      CreateGrommunioMailbox=1
#      OnlyCreateGrommunioMailbox=0
#    In this case, the script creates the mailbox and imports the Kopano data,
#    then creates the next mailbox and imports the Kopano data, and so on.
#
#    If the mailboxes should be created by the script before the actual migration.
#    This is a two-pass migration. First, all mailboxes are created, and in the 2nd pass, the Kopano data is migrated:
#      CreateGrommunioMailbox=1
#      OnlyCreateGrommunioMailbox=1
#    This is especially useful for large migrations. The mailboxes are created in advance,
#    the users work with Grommunio immediately, but still have empty mailboxes,
#    new mails arrive in the mailboxes and the old mails are migrated one by one.
#    For the second pass, set the variables like this:
#      CreateGrommunioMailbox=0
#      OnlyCreateGrommunioMailbox=0
#
#    When the migration is running unattended:
#	StopOnError=0
#    Otherwise, the script waits for a command from the admin in case of an error and that
#    the whole night long, thereby destroying valuable migration time.
#
#    The other settings are explained in the variables.
#
# 7. Test the migration
#    Run the migration in GNU screen (/usr/bin/screen) to avoid broken migrations due to lost connections.
#
# 8. If you delete all mailboxes and Public Store on grommunio,
#    restart the grommunio server or its services before starting the migration again, to clear all caches.
#
# 9. clean up the grommunio server
#
# 9.1. remove sshfs from grommunio server
#      grommunio Appliance / SUSE: zypper remove sshfs
#      Debian / Ubuntu: apt-get remove --purge sshfs
#
# 9.2. remove the mount directory
#      rmdir /mnt/kopano/
#
#
# Scripts and tools for Kopano to grommunio migration:
#
# The main migration script - this script
# https://github.com/grommunio/gromox/blob/master/tools/kopano2grommunio.sh
#
# Mailbox/user list creation script for Kopano server
# https://github.com/grommunio/gromox/blob/master/tools/create_k2g_migration_lists.sh
#
# kdb-uidextract-limited - create the mapping file, single server environment
# https://github.com/grommunio/gromox/blob/master/tools/kdb-uidextract-limited
# https://docs.grommunio.com/man/kdb-uidextract-limited.8.html
#
# kdb-uidextract - create the mapping file, multi-server environment
# https://github.com/grommunio/gromox/blob/master/tools/kdb-uidextract
# https://docs.grommunio.com/man/kdb-uidextract.8.html
#
# gromox-kdb2mt - Utility for analysis/import of Kopano mailboxes
# https://docs.grommunio.com/man/gromox-kdb2mt.8.html
#
# gromox-mt2exm — Utility for importing various mail items
# https://docs.grommunio.com/man/gromox-mt2exm.8.html
#
#
# Variables to be set by the user of this script
#
# The Kopano server of which we mount the attachment store from this server
KopanoServer="kopano.example.com"
#
# Login for the Kopano server
KopanoUser="root"

# The KopanoUser password. Leave empty to use certificate-based authentication.
KopanoUserPWD="Secret_root_Password"
KopanoUserPWD=""

# Path on the Kopano server to the Kopano attachment store
KopanoAttachments="/srv/kopano/attachments/"

# Normal operation, ssh mount the store =1, use 0 if the store is already mounted like an S3 bucket
# Make sure that the attachments are accessible at $GrommunioMount
MountKopanoAttachments=1

# Path on the grommunio server where the Kopano attachments are mounted
GrommunioMount="/mnt/kopano/"

# MSYQL server for Kopano database. Typically the same server as the Kopano server.
KopanoMySqlServer=$KopanoServer

# MYSQL user for Kopano database
KopanoMySqlUser="GrommunioUser"

# Password for MySQL user for Kopano database
KopanoMySqlPWD="Secret_MySQL_Password"

# The Kopano MySQL database, usually "kopano" but, on older installations, possibly "zarafa"
#KopanoDB="zarafa"
KopanoDB="kopano"

# The migration list containing the grommunio mailbox names and the Kopano login names or store IDs
MigrationList="/tmp/k2g_list.txt"

# The mapping file contains mappings for Zarafa addresses to MAPI addresses
KdbUidMap="/tmp/kdb-uidextract.map"

# Create a sample $MigrationList file. An existing $MigrationList will not be overwritten.
# For normal migration, set this variable to 0.
CreateSampleMigrationList=0

# Create the grommunio mailbox before migration. 1=yes, 0=no.
# This only works with an LDAP user source.
CreateGrommunioMailbox=1

# Only create mailboxes without data migration. 1=yes, 0=no.
# This sets CreateGrommunioMailbox=1.
OnlyCreateGrommunioMailbox=0

# Wait after each mailbox migration and allow exiting. 1=wait, 0=continue.
# See $STOP_MARKER how to interrupt migration.
# It is also possible to interrupt migration with 'X' after every mailbox.
WaitAfterImport=0

# Stops the script if a mailbox creation or migration error occurs. 1=stop, 0=continue.
# For unattended migrations, WaitAfterImport=0 and StopOnError=0 must be set.
StopOnError=1

# The language for mailbox folders.
# The languages can be found in: /usr/share/grommunio-admin-api/res/storelangs.json
MailboxLanguage="de_DE"

# Stop marker. If $WaitAfterImport=0, create this file and migration will be interrupted after current mailbox.
STOP_MARKER="/tmp/kopano2grommunio.STOP"

# Migration log file
LOG="/tmp/kopano2grommunio.log"

# From here on, no code or variables need changing by the user of this script.
#
# Trap function for cleanup
finish ()
{
	# Your cleanup code here
	echo ""
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
Write-MLog ()
{
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
		LEVEL="    "
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

# main code starts here
Write-MLog "" white

# create sample migration list file
if [[ $CreateSampleMigrationList -eq 1 ]]; then
	if [[ -f "$MigrationList" ]]; then
		Write-MLog "The file $MigrationList exists, we will *not* overwrite $MigrationList." red
		Write-MLog "Rename or remove $MigrationList and try again." red
		exit 1
	fi
	# sample content
	{
		echo "# Sample user list for Kopano 2 grommunio migration"
		echo "# mail address,Kopano login name|store GUID,' '|0|1"
		echo "# "
		echo "# Migrate the Public Store"
		echo "@domain.com,<Public Store GUID>"
		echo "# "
		echo "# Migrate users with mail address and Kopano login name, type:0"
		echo "user1@domain.com,user1,0"
		echo "user2@domain.com,user2,0"
		echo "# "
		echo "# Migrate a user but specify the Kopano store GUID instead of Kopano login, type:1"
		echo "user3@domain.com,<User 3 store GUID>,1"
	} > $MigrationList

	Write-MLog "" white
	Write-MLog "Sample $MigrationList have been created." green
	Write-MLog "Populate the mail addresses, login names and types." green
	Write-MLog "Last, set \$CreateSampleMigrationList=0 and start the migration." green
	#Write-MLog "" white
	#echo "sed -i s/^CreateSampleMigrationList=1/CreateSampleMigrationList=0/ $0"
	sed -i "s/^CreateSampleMigrationList=1/CreateSampleMigrationList=0/" "$0"
	exit 0
fi

# find and check the required commands
SSHFS="$(which sshfs 2>/dev/null)"
# openSUSE 15.4 provides fusermount3
FUSERMOUNT="$(which fusermount3 2>/dev/null)"
if [[ -z $FUSERMOUNT ]];then
	# openSUSE 15.3 and Debian 11 provide fusermount
	FUSERMOUNT="$(which fusermount 2>/dev/null)"
fi
#
for File in "$SSHFS" "$FUSERMOUNT";
do
	if [[ -z $File ]]; then
		Write-MLog "Error: command SSHFS or FUSERMOUNT not found, aborting." red
		exit 1 # terminate and indicate error
	fi
done

# check for required data files
for File in "$MigrationList" "$KdbUidMap";
do
	if [[ ! -f $File ]]; then
		Write-MLog "Error: data file: $File not found, aborting." red
		exit 1 # terminate and indicate error
	fi
done

# Main migration logic

# Statistics:
MailboxesTotal=0
#MailboxesSkipped=0
MailboxesCreated=0
MailboxesCreateFailed=0
MailboxesImported=0
MailboxesImportFailed=0
CreateErrorsMBX=""
ImportErrorsMBX=""

Write-MLog "" white
Write-MLog "" white
Write-MLog "===========================================================================" none
Write-MLog "" white
Write-MLog "" white
Write-MLog "Kopano 2 grommunio migration start" cyan

#Write-MLog "MSG red    " "red"
#Write-MLog "MSG yellow " "yellow"
#Write-MLog "MSG green  " "green"
#Write-MLog "MSG cyan   " "cyan"
#Write-MLog "MSG white  " "white"
#Write-MLog "MSG unknown" "unkn"

# create mount directory if it does not exist
if [[ ! -d "$GrommunioMount" ]]; then
	mkdir -p $GrommunioMount | tee -a $LOG
	Write-MLog "Create mount directory $GrommunioMount" white
	Write-MLog "" white
fi

if [[ MountKopanoAttachments -eq 1 ]]; then
	Write-MLog "Mount attachment directory: $GrommunioMount" yellow
	# mount the attachment directory
	if [[ -z "$KopanoUserPWD" ]]; then
		# certificate login
		Write-MLog "Enter Public Server Key Pass Phrase in next Line" yellow
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
else
	Write-MLog "Do *not* mount attachment directory: $GrommunioMount" yellow
	Write-MLog "Do *not* verify existence of attachment directory: $GrommunioMount" yellow
fi

if [[ $OnlyCreateGrommunioMailbox -eq 1 ]]; then
	Write-MLog "Only create mailboxes but do not migrate data." yellow
	CreateGrommunioMailbox=1
fi

Write-MLog "" white
#
# $MigMBox    - is the grommunio mailbox
# $KopanoUser - the Kopano login name
# $IsID       - Mail address = 0, Kopano store GUID = 1
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
	Write-MLog "We found mailbox: $MigMBox and Kopano user/GUID: $KopanoUser, ID: $IsID in list file" green

	MailboxesTotal=$((MailboxesTotal+1))
	SkipImportCreateError=0

	if [[ $MigMBox =~ ^@.* ]]; then
		Write-MLog "This is the Kopano public store, do not create a mailbox for: $MigMBox" yellow
	else
		if [[ $CreateGrommunioMailbox -eq 1 ]]; then
			Write-MLog "Try to create the mailbox: $MigMBox" yellow
			grommunio-admin ldap downsync -l $MailboxLanguage "$MigMBox" | tee -a $LOG
			ExitCode=${PIPESTATUS[0]}
			# currently (Jan. 2024) grommunio-admin always return error code 0 = success,
			# this prevents the error detection in this step. [DESK-1609]
			if [[ $ExitCode -eq 0 ]]; then
				# OK
				MailboxesCreated=$((MailboxesCreated+1))
				Write-MLog "Mailbox: $MigMBox created successfully" green
			else
				# Failed
				MailboxesCreateFailed=$((MailboxesCreateFailed+1))
				CreateErrorsMBX+=" $MigMBox"
				SkipImportCreateError=1
				Write-MLog "Cannot create mailbox: $MigMBox, error $ExitCode" red
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
			Write-MLog "This is the Kopano public store (GUID: $KopanoUser) for domain: $MigMBox" yellow
			(SQLPASS="$KopanoMySqlPWD" gromox-kdb2mt -s --user-map "$KdbUidMap" --sql-host "$KopanoMySqlServer" --sql-user "$KopanoMySqlUser" --sql-db "$KopanoDB" --mbox-guid "$KopanoUser" --src-attach "$GrommunioMount" | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a "$LOG"
			ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
		else
			if [[ $IsID -eq 0 ]]; then
				Write-MLog "Migration of mailbox $MigMBox with Kopano login $KopanoUser start" yellow
				# add parameter -s to import into correct folders. eg: gromox-kdb2mt -s ....
				(SQLPASS="$KopanoMySqlPWD" gromox-kdb2mt -s --user-map "$KdbUidMap" --sql-host "$KopanoMySqlServer" --sql-user "$KopanoMySqlUser" --sql-db "$KopanoDB" --mbox-mro "$KopanoUser" --src-attach "$GrommunioMount" | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a "$LOG"
				ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
			else
				Write-MLog "Migration of mailbox $MigMBox with Kopano GUID $KopanoUser start" yellow
				# add parameter -s to import into correct folders. eg: gromox-kdb2mt -s ....
				(SQLPASS="$KopanoMySqlPWD" gromox-kdb2mt -s --user-map "$KdbUidMap" --sql-host "$KopanoMySqlServer" --sql-user "$KopanoMySqlUser" --sql-db "$KopanoDB" --mbox-guid "$KopanoUser" --src-attach "$GrommunioMount" | gromox-mt2exm -u "$MigMBox") 2>&1 | tee -a "$LOG"
				ExitCode=$(( PIPESTATUS[0] + PIPESTATUS[1] ))
			fi
		fi
		if [[ $ExitCode -eq 0 ]]; then
			# OK
			MailboxesImported=$((MailboxesImported+1))
			Write-MLog "Mailbox: $MigMBox migrated successfully" green
		else
			# Failed
			MailboxesImportFailed=$((MailboxesImportFailed+1))
			ImportErrorsMBX+=" $MigMBox,"
			Write-MLog "Cannot migrate mailbox: $MigMBox, error $ExitCode" red
			# Wait for Admin to make a decision.
			[[ $StopOnError -eq 1 ]] && WaitAfterImport=1
		fi
	else
		# Try migrate of next mailbox
		SkipImportCreateError=0
		if [[ $OnlyCreateGrommunioMailbox -eq 1 ]]; then
			Write-MLog "Skipped migration of mailbox: $MigMBox, to do: only create mailbox" green
		else
			Write-MLog "Skipped migration of mailbox: $MigMBox, to do: creation error" red
		fi
	fi
	Write-MLog "Migration of mailbox $MigMBox end" yellow

	Write-MLog "" "white"
	Write-MLog "Total of $MailboxesTotal mailboxes processed, $MailboxesCreated mailboxes created, $MailboxesImported mailboxes migrated, " yellow
	Write-MLog "$MailboxesCreateFailed mailboxes creation failed, $MailboxesImportFailed migrations failed." yellow
	Write-MLog "" "white"
	#
	# if the $STOP_MARKER exists, interrupt migration and ask the Admin
	if [[ -f "$STOP_MARKER" ]]; then
		WaitAfterImport=1
		Write-MLog "Stop marker: $STOP_MARKER found, interrupting migration." cyan
	fi
	#
	# type "X" to ask the Admin
	if [[ $WaitAfterImport -eq 0 ]]; then
		Write-MLog "Type 'X' to interrupt migration ..." cyan
		read -s -n 1 -t 0.5 key <&$stdin  # -s: do not echo input character, -n 1: read only 1 character (separate with space), -t 1: wait 1 seconds
		if [[ "$key" == "X" ]]; then
			WaitAfterImport=1
			Write-MLog "'X' pressed, interrupting migration." cyan
		fi
	fi
	#
	# Ask the Admin after migration of mailbox
	[[ $WaitAfterImport -eq 0 ]] && continue
	#
	decision="Y"
	OK=0
	while [[ $OK -eq 0 ]]
	do
		Write-MLog "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " none
		read -r -p "Do you want to proceed with the next mailbox [Y]es [A]bort [C]ontinue? " -n1 decision <&$stdin
		decision=${decision^^}
		echo "";
		# echo " $decision"
		case $decision in
		"Y")
			Write-MLog "Migrate next mailbox" green
			OK=1
			;;
		"A")
			Write-MLog "Exit on Admin request." red
			OK=1
			;;
		"C")
			Write-MLog "Continue without future questions until errors" green
			WaitAfterImport=0
			OK=1
			;;
		esac
	done
	# Do we want to exit the migrations loop?
	[[ $decision == "A" ]] && break
done <"$MigrationList"

Write-MLog "" white
Write-MLog "Migration done, clean up" cyan

# Migration done, clean up
Write-MLog "Unmount attachment directory: $GrommunioMount" yellow
# Unmount the directory
$FUSERMOUNT -u $GrommunioMount | tee -a $LOG

# Print summary
Write-MLog "" white
Write-MLog "Total of $MailboxesTotal mailboxes processed" green

if [[ $CreateGrommunioMailbox -eq 1 ]]; then
	Write-MLog "$MailboxesCreated mailboxes created" green
	if [[ $MailboxesCreateFailed -ne 0 ]]; then
		Write-MLog "$MailboxesCreateFailed mailboxes creation failed" red
		Write-MLog "Affected mailboxes: $CreateErrorsMBX" red
	fi
fi
Write-MLog "$MailboxesImported mailboxes migrated" green
if [[ $MailboxesImportFailed -ne 0 ]]; then
	Write-MLog "$MailboxesImportFailed mailboxes migrated with errors or migration failed" red
	Write-MLog "Affected mailboxes: $ImportErrorsMBX " red
fi
Write-MLog "Kopano 2 grommunio migration done." cyan
#
# --- the end ---
#
# vim: syntax=bash ts=4 sw=4 sts=4 sr et :

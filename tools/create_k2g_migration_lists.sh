#!/bin/bash
#
# A Shell script to generate the Kopano user list for Grommunio migration.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
# Authors: Walter Hofstaedtler <walter@hofstaedtler.com>
#
# Based on an idea of:
# https://forum.kopano.io/topic/2049/display-firstname-lastname-email-lastlogon-mailbox-size/3
#
#
# Overview:
# The script, generates two files, first file for Kopano server and second file for Kopano archiver.
# If no Kopano archiver users are found, the Kopano archiver list file will be deleted.
# The output of this script is usable for kopano2grommunio.sh migration script.
#
# Script writes 3 lines for every user:
# For Kopano Server user:
# # <KopanoLoginName>, K: <Nr>, active: [yes/no]
# # <MailAddress>,<KopanoStoreGUID>,1
#   <MailAddress>,<KopanoLoginName>,0
#
# For Kopano archiver user:
# # <KopanoLoginName>, A: <Nr>, active: [yes/no]
# # <MailAddress>,<KopanoArchiverStoreGUID>,1
#   <MailAddress>,<KopanoLoginName>,0
# 
# The line <MailAddress>,<KopanoLoginName>,0 is active to be used for migration. If the <KopanoLoginName> is 
# ambiguous, use the line with <KopanoStoreGUID>,1 or <KopanoArchiverStoreGUID>,1 to migrate this mailbox.
#
#
# Versions:
# 20221014, v1.0, ignore: postmaster@localhost,SYSTEM and headings.
# 20221022, v1.1, report correct archiver guid, add summary.
# 20221025, v1.2, added some explanations.
#
#
# Notice:
# This script assumes a correct working Kopano server and if used a correct working Kopano archiver.
# Script is compatible with any Linux target source.
# Important, this script needs a bash, the smaller POSIX sh is not sufficient.
#
#
# Instructions:
# 1. setup the variables: MigrationList and MigrationListArchiv.
# 2. launch this script on the Kopano Server.
# 3. modify the list files to fit your needs.
# 4. move the migration list files to the grommunio server and configure kopano2grommunio.sh to use the lists.
# 5. migrate the users/mailboxes to grommunio.
#
#
# Variables to be set by the user of this script.
#
# The list containing the grommunio mailbox names, Kopano login names and store GUIDs for Kopano server.
MigrationList="/tmp/k2g_list_raw.txt"
#
# The list containing the grommunio mailbox names, Kopano login names and store GUIDs for Kopano archiver.
MigrationListArchiv="/tmp/k2g_list_a_raw.txt"
#
# From here on, no code or variables need changing by the user of this script
#
TempFile="/tmp/oneuser.txt"
#
# Statistics:
MailboxesTotal=0
MailboxesSize=0
ArchivboxesTotal=0
ArchivboxesSize=0
#
# sample content
{
    echo "# Sample user list for Kopano 2 grommunio migration"
    echo "# mail address,Kopano login name|store GUID,' '|0|1"
    echo "# "
    echo "# Migrate the Public Store"
    echo "#@domain.com,<Public Store GUID>"
    echo "# "
    echo "# Migrate users with mail address and Kopano login name, type:0"
    echo "#user1@domain.com,user1,0"
    echo "#user2@domain.com,user2,0"
    echo "# "
    echo "# Migrate a user but specify the Kopano store GUID instead of Kopano login, type:1"
    echo "#user3@domain.com,<User 3 store GUID>,1"
    echo "#"
    echo "# Start of customer data:"
    echo "#"
} > $MigrationList
#
# sample content
{
    echo "# Sample user list for Kopano Archiver 2 grommunio migration"
    echo "# mail address,Kopano login name|store GUID,' '|0|1"
    echo "# "
    echo "# Migrate the Public Store"
    echo "#@domain.com,<Public Store GUID>"
    echo "# "
    echo "# Migrate users with mail address and Kopano login name, type:0"
    echo "#user1@domain.com,user1,0"
    echo "#user2@domain.com,user2,0"
    echo "# "
    echo "# Migrate a user but specify the Kopano store GUID instead of Kopano login, type:1"
    echo "#user3@domain.com,<User 3 store GUID>,1"
    echo "#"
    echo "# Start of customer data:"
    echo "#"
} > $MigrationListArchiv
#
# get the Kopano users
UserList=$(kopano-admin -l | awk '{print $1}')
#
# read data for every user
for i in $UserList
do
    # if LoginName is SYSTEM, ignore this line
    if [ "$i" = "SYSTEM" ]; then
        echo "Skipping SYSTEM account."
        continue
    fi
    if [ "$i" = "User" ]; then
        echo "Skipping User line."
        continue
    fi
    if [ "$i" = "Username" ]; then
        echo "Skipping Username line."
        continue
    fi
    if [[ "$i" = *"-----------------"* ]]; then
        echo "Skipping ----------------- line."
        continue
    fi
    #
    # Statistics
    MailboxesTotal=$((MailboxesTotal+1))
    # get the user data
    arcguid=""
    kopano-admin --details "$i" > $TempFile 2>/dev/null
    size=$(cat $TempFile | grep "Current store"|cut --delimiter=":" -f 2 | cut -d " " -f1)
    #ll=$(cat $TempFile | grep "Last logon"|cut --delimiter=":" -f 2| cut -c-12)
    ac=$(cat $TempFile | grep "Active"|cut --delimiter=":" -f 2)
    guid=$(cat $TempFile | grep "Store GUID"|cut --delimiter=":" -f 2)
    ma=$(cat $TempFile | grep "Emailaddress"|cut --delimiter=":" -f 2)
    arcguid=$(cat $TempFile | grep "Archive GUID"|cut --delimiter=":" -f 2)
    #
    # strip spaces from guid
    guid=${guid//[[:blank:]]/}
    # process results
    echo "$ma, $i   - Size: $size MB, Nr.: $MailboxesTotal, Active: $ac" | xargs echo
    # write migration list file for Kopano server
    {
        echo "# $i, K: $MailboxesTotal, size: $size MB, active: $ac" | xargs echo
        echo "# $ma,$guid,1" | xargs echo
        echo "$ma,$i,0" | xargs echo
    } >> $MigrationList
    #
    # if size contains 2 numbers, we have a Kopano archiver user/mailbox
    # remove dot from number!
    size="${size//.}"
    # strip spaces from number
    size=${size//[[:blank:]]/}
    # split size in an array and in 2 numbers
    IFS=$'\n'
    SIZE_ARRAY=($( echo "$size" | sed ':a;N;$!ba;s/\r\n/ /g' ))
    unset IFS
    size_store=$( echo "${SIZE_ARRAY[@]}" | cut -d " " -f1 )
    size_archive=$( echo "${SIZE_ARRAY[@]}" | cut -d " " -f2 )
    # remove leading zeros, bash treads numbers with leading 0 as octal
    size_store=$((${size_store#0}+0))
    # multiply by 10 to get MB
    size_store=$((size_store*10))
    # Statistics
    MailboxesSize=$((MailboxesSize+size_store))
    #
    # archiver
    # remove leading zeros, bash treads numbers with leading 0 as octal
    size_archive=$((${size_archive#0}+0))
    # multiply by 10 to get MB
    size_archive=$((size_archive*10))
    #
    # if $size_store and $size_archive is same size, user do *not* have a archive
    if [ "$size_store" -eq "$size_archive" ]; then
        size_archive=0
    fi
    # if no $arcguid found, user do *not* have a archive
    if [[ "$arcguid" = "" ]]; then
        size_archive=0
    fi
    #
    if [ "$size_archive" -gt 0 ]; then
        # we have an archiver user/mailbox
        ArchivboxesSize=$((ArchivboxesSize+size_archive))
        ArchivboxesTotal=$((ArchivboxesTotal+1))
        echo "$i is archive user Nr.: $ArchivboxesTotal, archive size: $((size_archive/1024)) GB."
        {
          echo "# $i, A: $ArchivboxesTotal, size: $((size_archive/1024)) GB, active: $ac" | xargs echo
          echo "# $ma,$arcguid,1" | xargs echo
          echo "$ma,$i,0" | xargs echo
        } >> $MigrationListArchiv
    fi
done
#
# remove temp file
rm $TempFile
# notify Admin.
echo ""
echo "Use $MigrationList to migrate online users, containing $MailboxesTotal online mailboxes, $((MailboxesSize/1024)) GB "
echo "# Use $MigrationList to migrate online users, containing $MailboxesTotal online mailboxes, $((MailboxesSize/1024)) GB " >> $MigrationList
#
if [ "$ArchivboxesTotal" -gt 0 ]; then
    echo "Use $MigrationListArchiv to migrate archiver users, containing $ArchivboxesTotal archiver mailboxes, $((ArchivboxesSize/1024)) GB"
    echo "# Use $MigrationListArchiv to migrate archiver users, containing $ArchivboxesTotal archiver mailboxes, $((ArchivboxesSize/1024)) GB" >> $MigrationListArchiv
  else
    echo "No Kopano archiver users found, deleting unneeded $MigrationListArchiv."
    rm "$MigrationListArchiv"
fi
echo ""
#
# --- the end ---
#
# vim: syntax=auto ts=4 sw=4 sts=4 sr noet :

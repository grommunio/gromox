The program adds or remove the PR_PROFILE_USER_SMTP_EMAIL_ADDRESS
property from one or more MAPI profiles. Starting with the KB 3172519
update, using the "Reply All" functionality in Outlook 2013 would place
one own's address in the To: field as well. Setting said property with
one's address cures Outlook's new behavior.

	cl -DUNICODE smtpaddr.cpp mapi32.lib

[Unit]
Description=Gromox IMAP server
Documentation=man:imap(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/imap
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

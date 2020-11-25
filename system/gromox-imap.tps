[Unit]
Description=Gromox IMAP server
Documentation=man:imap(8gx)
PartOf=gromox-mra.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/imap

[Install]
WantedBy=multi-user.target

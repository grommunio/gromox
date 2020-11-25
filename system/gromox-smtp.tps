[Unit]
Description=Gromox SMTP server
Documentation=man:smtp(8gx)
PartOf=gromox-mta.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/smtp

[Install]
WantedBy=multi-user.target

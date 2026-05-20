[Unit]
Description=The Gromox Information Store
Documentation=man:istore(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/istore
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

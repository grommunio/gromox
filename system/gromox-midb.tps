[Unit]
Description=Gromox midb service
Documentation=man:midb(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/midb
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

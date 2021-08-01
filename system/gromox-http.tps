[Unit]
Description=Gromox HTTP service
Documentation=man:http(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/http
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

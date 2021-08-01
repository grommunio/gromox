[Unit]
Description=Gromox zcore service
Documentation=man:zcore(8gx)
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/zcore
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

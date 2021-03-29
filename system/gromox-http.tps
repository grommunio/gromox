[Unit]
Description=Gromox HTTP service
Documentation=man:http(8gx)
PartOf=gromox-exch.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/http
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target

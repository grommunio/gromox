[Unit]
Description=Gromox local delivery agent frontend
Documentation=man:delivery-queue(8gx)
PartOf=gromox-mta.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/delivery-queue
ExecReload=/bin/kill -HUP $MAINPID
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

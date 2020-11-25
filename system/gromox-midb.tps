[Unit]
Description=Gromox midb service
Documentation=man:midb(8gx)
PartOf=gromox-exch.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/midb

[Install]
WantedBy=multi-user.target

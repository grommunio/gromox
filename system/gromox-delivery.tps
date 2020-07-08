[Unit]
Description=Gromox mail spooler
Documentation=man:delivery(8gx)
PartOf=gromox-mta.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/delivery

[Install]
WantedBy=multi-user.target

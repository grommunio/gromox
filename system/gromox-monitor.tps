[Unit]
Description=Gromox monitor service
Documentation=man:monitor(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/monitor

[Install]
WantedBy=multi-user.target

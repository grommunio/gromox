[Unit]
Description=Gromox event service
Documentation=man:event(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
User=gromox
ExecStart=@libexecdir@/gromox/event

[Install]
WantedBy=multi-user.target

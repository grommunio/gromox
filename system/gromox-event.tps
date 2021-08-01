[Unit]
Description=Gromox event service
Documentation=man:event(8gx)

[Service]
Type=simple
User=gromox
ExecStart=@libexecdir@/gromox/event
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

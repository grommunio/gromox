[Unit]
Description=Gromox timer service
Documentation=man:timer(8gx)

[Service]
Type=simple
User=gromox
ExecStart=@libexecdir@/gromox/timer
ProtectSystem=yes

[Install]
WantedBy=multi-user.target

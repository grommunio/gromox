[Unit]
Description=Gromox supervisor service
Documentation=man:supervisor(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/supervisor

[Install]
WantedBy=multi-user.target

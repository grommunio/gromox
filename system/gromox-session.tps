[Unit]
Description=Gromox session service
Documentation=man:session(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/session

[Install]
WantedBy=multi-user.target

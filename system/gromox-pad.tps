[Unit]
Description=Gromox pad service
Documentation=man:pad(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/pad

[Install]
WantedBy=multi-user.target

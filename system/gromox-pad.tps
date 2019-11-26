[Unit]
Description=Gromox pad service
Documentation=man:pad(8gx) man:pad.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/pad

[Install]
WantedBy=multi-user.target

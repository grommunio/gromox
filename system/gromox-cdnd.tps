[Unit]
Description=Gromox cdnd service
Documentation=man:cdnd(8gx) man:cdnd.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/cdnd

[Install]
WantedBy=multi-user.target

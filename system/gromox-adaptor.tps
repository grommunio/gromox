[Unit]
Description=Gromox adaptor service
Documentation=man:adaptor(8gx) man:adaptor.cfg(5gx)
PartOf=gromox-sa.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/adaptor

[Install]
WantedBy=multi-user.target

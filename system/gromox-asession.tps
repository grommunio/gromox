[Unit]
Description=Gromox asession service
Documentation=man:asession(8gx) man:asession.cfg(5gx)
PartOf=gromox-agent.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/asession

[Install]
WantedBy=multi-user.target

[Unit]
Description=Gromox asensor service
Documentation=man:asensor(8gx) man:asensor(5gx)
PartOf=gromox-agent.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/asensor

[Install]
WantedBy=multi-user.target

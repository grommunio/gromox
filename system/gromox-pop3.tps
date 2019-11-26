[Unit]
Description=Gromox POP3 server
Documentation=man:pop3(8gx) man:pop3.cfg(5gx)
PartOf=gromox-mra.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/pop3

[Install]
WantedBy=multi-user.target

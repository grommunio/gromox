[Unit]
Description=Gromox IMAP server
Documentation=man:imap(8gx)
PartOf=gromox-mra.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/imap

[Install]
WantedBy=multi-user.target

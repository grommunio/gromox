[Unit]
Description=Gromox cidb service
Documentation=man:cidb(8gx) man:cidb.cfg(5gx)
PartOf=gromox-archive.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/cidb

[Install]
WantedBy=multi-user.target

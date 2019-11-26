[Unit]
Description=Gromox midb service
Documentation=man:midb(8gx) man:midb.cfg(5gx)
PartOf=gromox-exch.target

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/midb

[Install]
WantedBy=multi-user.target

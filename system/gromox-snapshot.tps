[Unit]
Description=Gromox snapshot job
Documentation=man:gromox-snapshot(8)
ConditionPathIsDirectory=/var/lib/gromox/user

[Service]
Type=oneshot
User=gromox
ExecStart=@libexecdir@/gromox/gromox-snapshot
PrivateDevices=no
PrivateNetwork=yes
PrivateUsers=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@default @file-system @basic-io @system-service

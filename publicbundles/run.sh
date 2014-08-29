#!/bin/sh
sudo mount /dev/sdb2 /home/wb/images/
cd /home/wb/experiments && /home/wb/work/build/prophet/qemu-release/i386-s2e-softmmu/qemu-system-i386 -m 512 -net user,tftp=/home/wb -net nic,model=ne2k_pci -usbdevice mouse  -monitor stdio -hda /home/wb/images/winxpsp3.raw.s2e -s2e-config-file /home/wb/work/workspace/prophet/publicbundles/config.lua

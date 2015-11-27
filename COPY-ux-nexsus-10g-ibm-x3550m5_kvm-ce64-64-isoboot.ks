auth  --useshadow  --enablemd5
## text
cmdline

firewall --enabled --trust eth0 --http --ftp --ssh --telnet --smtp --port=imap:tcp,,imaps:tcp,,https:tcp,,dns:udp,,dns:tcp,,pop3:tcp,,pop3s:tcp,,dns:udp,,dns:tcp
firstboot --disable
services --disabled xfs,cpuspeed,readahead,microcode_ctl,pcmcia,gpm,cman,openais,dnsmasq,multipathd,iptables,ip6tables,iscsi,iscsid,kdump,snmptrapd,gfs2,mdmonitor,ksm,ksmtuned,virt-who,xfs,mdmonitor
services --enabled ipmi,haldaemon,snmpd,rsyslog,named,nscd,sysstat,ntpd,acpid,cgconfig,cgred
keyboard jp106
lang ja_JP.UTF-8
cdrom
##url --url=http://10.110.103.250/cblr/links/ce64-64-x86_64 --proxy=http://10.110.103.250:18080/
##repo --name=epel-6-x86_64 --baseurl=http://10.110.103.250/cobbler/repo_mirror/epel-6-x86_64
##repo --name=ce64-cr-x86_64 --baseurl=http://10.110.103.250/cobbler/repo_mirror/ce64-cr-x86_64
##repo --name=ce64-extras-x86_64 --baseurl=http://10.110.103.250/cobbler/repo_mirror/ce64-extras-x86_64
##repo --name=ce64-updates-x86_64 --baseurl=http://10.110.103.250/cobbler/repo_mirror/ce64-updates-x86_64
##repo --name=gel-el6-noarch --baseurl=http://10.110.103.250/cobbler/repo_mirror/gel-el6-noarch
##repo --name=gel-el6-x86_64 --baseurl=http://10.110.103.250/cobbler/repo_mirror/gel-el6-x86_64
##repo --name=el6-ibm --baseurl=http://10.110.103.250/cobbler/repo_mirror/el6-ibm
##repo --name=source-1 --baseurl=http://10.110.103.250/cobbler/ks_mirror/ce64-64-x86_64

    network --bootproto=dhcp  --device=eth0 --onboot=on
    ## network --bootproto=static --ip=169.254.95.130 --netmask=255.255.0.0 --device=usb0 --onboot=on
## ============================================================
## reboot
reboot --eject
## ============================================================

rootpw  --iscrypted $1$ASCj4mm1$.CIXYBsw6hzxj9XtRhPhV1
## rootpw Xhogehoge
selinux --disabled
skipx
timezone Asia/Tokyo
install
zerombr

        ## bootloader --location=partition --driveorder=sda --append="nomodeset crashkernel=auto"
  bootloader --location=mbr --append="nomodeset crashkernel=auto"


## clearpart --none
##clearpart --all --drives=sda,sdb
clearpart --all


##     part /boot/efi --fstype=efi  --maxsize=200 --size=50 --ondisk=sda --grow --asprimary
part /boot --fstype=ext3 --size=500 --ondisk=sda --asprimary

part pv.008003 --size=1 --grow --ondisk=sda --asprimary
volgroup vg00 pv.008003 


  logvol swap --fstype=swap --name=lv01 --vgname=vg00 --size=12288
    logvol /    --fstype=ext4 --name=lv00 --vgname=vg00 --size=8192 --grow



%pre
export LC_ALL=C
export LANG=C
set -x -v
exec 1>/tmp/ks-pre.log 2>&1

## Once root's homedir is there, copy over the log.
while : ; do
    busybox sleep 10
    if [ -d /mnt/sysimage/root ]; then
        cp /tmp/ks-pre.log /mnt/sysimage/root/
        logger "Copied %pre section log to system"
        break
    fi
done &


## wget "http://10.110.103.250/cblr/svc/op/trig/mode/pre/system/vn0c0353.apu8.internal-gmo" -O /dev/null

echo "--== kick_mode : x3550m5"
echo "--== kick_mode : x3550m5" > /dev/console
echo "--==   kick start   =="

## ----------------------------------------------
## network : csv setup : 02 : start
##
## My Host Configration
## host_csv_file='iso-setup-vm0a-csv.txt'
mkdir -p /mnt/sysimage/iso
mount /dev/sr0 /mnt/sysimage/iso

## ##
host_csv_file='iso-setup-vn2c-csv.txt'
unit_info_file='iso-setup-unit-info.txt'
## 
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /mnt/sysimage/root/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /tmp/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /var/tmp/
 
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /mnt/sysimage/root/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /tmp/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /var/tmp/
 
## mkdir -p /mnt/sysimage/data
## if [ -f /mnt/sysimage/iso/data.iso ]; then
## mount -oloop /mnt/sysimage/iso/data.iso /mnt/sysimage/data
## rsync -arv /mnt/sysimage/data/ /tmp/
## rsync -arv /mnt/sysimage/data/ /var/tmp/
## fi
## ----------------------------------------------

##
if [ -f /dev/shm/iso-setup-vn2c-csv.txt ]; then
  cp -avf /dev/shm/iso-setup-vn2c-csv.txt /root/
elif [ -f /tmp/iso-setup-vn2c-csv.txt ]; then
  cp -avf /tmp/iso-setup-vn2c-csv.txt /root/
elif [ -f /var/tmp/iso-setup-vn2c-csv.txt ]; then
  cp -avf /var/tmp/iso-setup-vn2c-csv.txt /root/
  sleep 12
fi
while : ; do
    sleep 10
    if [ -f /root/iso-setup-vn2c-csv.txt ]; then
        ls -l /root/iso-setup-vn2c-csv.txt
        logger "system setup host list file check"
        break
    fi
done &
if [ -f /dev/shm/iso-setup-unit-info.txt ]; then
  cp -avf /dev/shm/iso-setup-unit-info.txt /root/
elif [ -f /tmp/iso-setup-unit-info.txt ]; then
  cp -avf /tmp/iso-setup-unit-info.txt /root/
elif [ -f /var/tmp/iso-setup-unit-info.txt ]; then
  cp -avf /var/tmp/iso-setup-unit-info.txt /root/
  sleep 12
fi
##
df  > /root/info-df
## ls -l /data/ > /root/info-dir-data
ls -l /tmp/ > /root/info-tmp
ls -l /var/tmp/ > /root/info-var-tmp

proxy_host="10.110.103.250"

export http_proxy="http://${proxy_host}:18080/"
export ftp_proxy="http://${proxy_host}:18080/"

## clean
## ip link set dev eth0 down
ip link set dev eth1 down
ip link set dev eth2 down
ip link set dev eth3 down
## cat > /etc/udev/rules.d/70-persistent-net.rules << __UDEV
##
cat > /etc/modprobe.d/bonding.conf << __EOF
alias bond0 bonding
__EOF

modprobe bonding
modprobe cdc_ether

## ----------------------------------------------
## bonding for Manage VLAN 302
ip link set eth1 down 

modprobe bonding mode=4 miimon=100 lacp_rate=fast xmit_hash_policy=layer3+4
modprobe 8021q

echo +eth1 > /sys/class/net/bond0/bonding/slaves 

ip link set bond0 up

ip link add link bond0 name bond0.544 type vlan id 544
## ----------------------------------------------

myip=0.0.0.0
myhostname="vn0c0353.apu8.internal-gmo"

ip addr show eth0 | grep 'link/ether ' > /var/tmp/info-eth0
ip addr show eth0 | grep "global eth0" | awk '{print $2}' > /var/tmp/info-ip-eth0

cat /var/tmp/info-eth0 | awk '{print $2 }' | sed -e 's/://g' > /var/tmp/info-eth0-mac
cat /var/tmp/info-eth0 | awk '{print $2 }' > /var/tmp/info-eth0-mac-base

## DHCP MacAddr / MacAddr_base
## macaddr=` /sbin/ip addr show eth0  |/usr/bin/awk '/link\/ether/{ gsub(/:/,""); print $2 }' `
macaddr=`cat /var/tmp/info-eth0-mac`
macaddr_base=`cat /var/tmp/info-eth0-mac-base`

## Manage IP : myip
##myip=` cat ${host_csv_file} | grep -i ${macaddr} |cut -f17 -d'|' `
myip_cnt=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f13 -d'|' | wc -l`
myip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f13 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  myip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f13 -d'|' `
fi

## IMM IP : imm_ip
imm_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f2 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  imm_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f2 -d'|' `
fi
imm_ip_d4=`echo ${imm_ip} | cut -f4 -d'.'`
imm_ip_d3=`echo ${imm_ip} | cut -f3 -d'.'`
imm_ip_d2=`echo ${imm_ip} | cut -f2 -d'.'`
imm_ip_d1=`echo ${imm_ip} | cut -f1 -d'.'`

## DHCP IP : dhcp_ip
## dhcp_ip=`cat /var/tmp/info-ip-eth0 | cut -d'/' -f1`
dhcp_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f17 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  dhcp_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f17 -d'|' `
fi

## admin file url : admin_file_url
admin_file_url="http://10.110.103.250/admin/${imm_ip_d4}/${imm_ip_d3}/admin-${imm_ip_d1}-${imm_ip_d2}-${imm_ip_d3}-${imm_ip_d4}.txt"

## [root@el6sg08 setup]# cat iso-setup-unit-info.txt  | grep MAN_GW_IP | cut -d'|' -f2
## 172.20.176.1
DEF_GW_IP=` cat /data/iso-setup-unit-info.txt  | grep MAN_GW_IP | cut -d'|' -f2 `
MAN_NETMASK=` cat /data/iso-setup-unit-info.txt  | grep MAN_NETMASK | cut -d'|' -f2 `

## HostName : myhostname
if [ ${myip} != '0.0.0.0' ];then
##myhostname=` cat ${host_csv_file} | grep -i ${macaddr} |cut -f16 -d'|' `
myhostname=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f12 -d'|' `
## myhost data
cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f12 -d'|' > /root/myhost-data.txt
if [ $myip_cnt -eq 0 ]; then
  myhostname=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f12 -d'|' `
  ## myhost data
  cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f12 -d'|' > /root/myhost-data.txt
fi


echo "hostname : ${myhostname} " > tee -a /root/myhostname.txt
echo "hostname : ${myhostname} " > /dev/console

## ----------------------------------------------
## Manage network up
ip addr add ${myip}/21 brd 10.110.119.255 dev bond0.544
ip link set dev bond0.544 up
## ----------------------------------------------

## dd if=/dev/zero of=/dev/sda bs=512 count=64
## /usr/sbin/parted -s /dev/sda mklabel gpt
## /usr/sbin/parted -s /dev/sda mkpart primary ext2 0 10M
## /usr/sbin/parted -s /dev/sda set 1 bios_grub on

## dd if=/dev/zero of=/dev/sdb bs=512 count=64
## /usr/sbin/parted -s /dev/sdb mklabel gpt
%end


%packages --ignoremissing
## @base
## @core
## epel-release
## acpid
## at
## cronie-noanacron
## crontabs
## logrotate
## ntp
## ntpdate
## openssh-clients
## openssh-server
## puppet
## puppetlabs-release
## rsync
## vixie-cron
## wget
## which
## yum
## -prelink
## -selinux-policy-targeted

@base
@core
@console-internet
@hardware-monitoring
@performance
tuned
tuned-utils
@japanese-support

netcf-devel.x86_64
netcf-libs.x86_64
netcf.x86_64

@java-platform
@large-systems
@system-management-messaging-client
@system-management-messaging-server
@network-file-system-client
@perl-runtime
@system-management-snmp
@server-platform
@system-management
@system-management-wbem
OpenIPMI
OpenIPMI-devel
OpenIPMI-libs
OpenIPMI-perl
OpenIPMI-python
OpenIPMI-tools
expect
pexpect
fuse
fuse-sshfs
gcc
gcc-c++
genisoimage
git
git-email
gnupg2
glibc-devel
hwdata
ipmitool
iproute
kernel
kernel-devel
kernel-headers
lftp
lshw
-pam_passwdqc
centos-release-cr
-libvirt-qmf
-qpid-cpp-server
-qpid-cpp-server-ssl
-matahari-broker
ltrace
lynx
-elinks
pax
perl
net-snmp
net-snmp-devel
net-snmp-libs
net-snmp-perl
net-snmp-python
net-snmp-utils
perl-Archive-Extract
perl-Archive-Tar
perl-Archive-Zip
perl-CPAN
perl-CPAN-DistnameInfo
perl-CPANPLUS
perl-Class-Singleton
perl-Clone
perl-Compress-Raw-Zlib
perl-Compress-Zlib
perl-Config-General
perl-Config-Properties
perl-Crypt-DES
perl-Crypt-PasswdMD5
perl-DBD-MySQL
perl-DBD-SQLite
perl-DBI
perl-DBIx-Simple
perl-Data-Compare
perl-Date-Manip
perl-DateTime
perl-Devel-CheckOS
perl-Digest-SHA1
perl-Email-Abstract
perl-Email-Date
perl-Email-Date-Format
perl-Email-Simple
perl-Error
perl-Error.noarch
perl-ExtUtils-CBuilder
perl-ExtUtils-MakeMaker
perl-ExtUtils-ParseXS
perl-File-Fetch
perl-File-Find-Rule
perl-File-Remove
perl-Git
perl-HTML-Parser
perl-HTML-Tagset
perl-IO-Compress-Base
perl-IO-Compress-Zlib
perl-IO-Zlib
perl-IPC-Cmd
perl-JSON
perl-JSON-XS
perl-Lingua-EN-Inflect
perl-Lingua-EN-Inflect-Number
perl-List-MoreUtils
perl-Locale-Maketext-Simple
perl-Log-Dispatch
perl-Log-Dispatch-FileRotate
perl-Log-Handler
perl-Log-Log4perl
perl-Log-Message
perl-Log-Message-Simple
perl-MIME-Lite
perl-MIME-Types
perl-Mail-Sender
perl-Mail-Sendmail
perl-MailTools
perl-Math-BigInt-GMP
perl-Module-Build
perl-Module-CoreList
perl-Module-Find
perl-Module-Info
perl-Module-Install
perl-Module-Pluggable
perl-Module-ScanDeps
perl-Net-SNMP
perl-Net-Telnet
perl-Number-Compare
perl-Object-Accessor
perl-PAR-Dist
perl-Package-Constants
perl-Params-Check
perl-Params-Validate
perl-Parse-CPAN-Meta
perl-Pod-Escapes
perl-Pod-Simple
perl-SGMLSpm
perl-Scalar-Properties
perl-String-CRC32
perl-Term-UI
perl-Test-Harness
perl-Test-Pod
perl-Test-Simple
perl-Text-Glob
perl-Text-Unidecode
perl-Time-HiRes
perl-Time-Piece
perl-TimeDate
perl-URI
perl-Unix-Syslog
perl-Unix-Uptime
perl-XML-DOM
perl-XML-Parser
perl-XML-RegExp
perl-YAML
perl-YAML-LibYAML
perl-YAML-Tiny
perl-common-sense
-php
-php-cli
-php-pear-MDB2
ntp
ntpdate
ntp-doc
ntp-perl
python-setuptools
rpm-build
rpm-devel
rsync
rsyslog
screen
sgpio
sqlite-devel
strace
sudo
syslinux
sysstat
tcsh
telnet
tog-pegasus
vconfig
vim-enhanced
wget
yum-fastestmirror
-yum-autoupdate
-hypervkvpd
epel-release
-dbus.i686
audit-libs.i686
compat-libstdc++-296.i686
compat-libstdc++-33.i686
cracklib.i686
cyrus-sasl-lib.i686
db4.i686
e2fsprogs-libs.i686
e2fsprogs-libs.x86_64
glibc.i686
keyutils-libs.i686
libcurl.i686
libgcc.i686
libidn.i686
libsepol.i686
libsepol.x86_64
libssh2.i686
libstdc++.i686
ncurses-libs.i686
nspr.i686
nss-softokn.i686
nss-util.i686
nss.i686
openldap.i686
pam.i686
pam.x86_64
readline.i686
sqlite.i686
zlib.i686
-dovecot
-spamassassin
-wireless-tools
-spice-gtk
-mesa-dri-drivers
-samba-common
-virt-viewer
-bfa-firmware
ibm_utl_asu
%end


## ============================================================


%post --nochroot --log=/mnt/sysimage/root/anaconda-post-inst-nochroot.log --erroronfail
#!/bin/bash
export LC_ALL=C
export LANG=C
##
log_mesg() {
/bin/echo
/bin/echo POST: $* > /dev/console
}

## ----------------------------------------------
## mount
mkdir -p /mnt/sysimage/iso
mount /dev/sr0 /mnt/sysimage/iso

## ##
host_csv_file='iso-setup-vn2c-csv.txt'
unit_info_file='iso-setup-unit-info.txt'
## 
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /mnt/sysimage/root/
## ## cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vm0a-csv.txt /dev/shm/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /tmp/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-vn2c-csv.txt /var/tmp/
 
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /mnt/sysimage/root/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /tmp/
cp -avf /mnt/sysimage/iso/isolinux/ks/iso-setup-unit-info.txt /var/tmp/
 
## mkdir -p /mnt/sysimage/data
## if [ -f /mnt/sysimage/iso/data.iso ]; then
## mount -oloop /mnt/sysimage/iso/data.iso /mnt/sysimage/data
## rsync -arv /mnt/sysimage/data/ /tmp/
## rsync -arv /mnt/sysimage/data/ /var/tmp/
## fi
## ----------------------------------------------
%end 


## ============================================================
%post --log=/anaconda-post-inst.log --erroronfail
export LC_ALL=C
export LANG=C
function log_mesg() {
/bin/echo
/bin/echo "POST: $*"
/bin/echo "POST: $*" > /dev/console
}


log_mesg "BEGIN POST SCRIPT"
export LC_ALL=C
export LANG=C

## Serial Console enable
echo "ttyS0" >> /etc/securetty
echo "ttyS1" >> /etc/securetty

## ----------------------------------------------
## network : pre setup : 01 : start
## Bonding module enable
cat > /etc/modprobe.d/bonding.conf << EOT
alias bond0 bonding
EOT
##
## resolver
cat > /etc/resolv.conf << EOT
nameserver 8.8.8.8
EOT
##
##
sed -i -e '/BOOTPROTO="dhcp"/d' \
  -e '/NM_CONTROLLED="yes"/d' \
  -e '/ONBOOT="no"/d' \
  /etc/sysconfig/network-scripts/ifcfg-usb0
cat >> /etc/sysconfig/network-scripts/ifcfg-usb0  << __EOF_USB
BOOTPROTO="static"
NM_CONTROLLED="no"
ONBOOT="yes"
IPADDR=169.254.95.130
NETMASK=255.255.0.0
__EOF_USB
##
## Bond0 Device
cat > /etc/sysconfig/network-scripts/ifcfg-bond0 << __EOT
DEVICE=bond0
NM_CONTROLLED=no
BOOTPROTO=none
USERCTL=no
ONBOOT=yes
BONDING_OPTS="mode=4 miimon=100 lacp_rate=fast xmit_hash_policy=layer3+4"
__EOT
##
## eth1 .. eth3 Configration
for target in ifcfg-eth1
do
TARGET=/etc/sysconfig/network-scripts/${target}
sed -i 's/NM_CONTROLLED="yes"/NM_CONTROLLED="no"/' ${TARGET}
sed -i 's/BOOTPROTO="dhcp"/BOOTPROTO="dhcp"/' ${TARGET}
cat >> ${TARGET} << __EOT
BOOTPROTO=none
MASTER=bond0
SLAVE=yes
USERCTL=no
__EOT
done
##
## Bond0+VLAN Configration
for target in 544 545 546 547
do
TARGET=/etc/sysconfig/network-scripts/ifcfg-bond0.${target}
cat >> ${TARGET} << __EOT
DEVICE=bond0.${target}
BOOTPROTO=none
USERCTL=no
NM_CONTROLLED=no
ONBOOT=yes
VLAN=yes
HOTPLUG=no
BRIDGE=br0.${target}
__EOT
done
##
## Bridge Configration
for target in 544 545 546 547
do
TARGET=/etc/sysconfig/network-scripts/ifcfg-br0.${target}
cat >> ${TARGET} << __EOT
DEVICE=br0.${target}
BOOTPROTO=none
USERCTL=no
NM_CONTROLLED=no
ONBOOT=yes
HOTPLUG=no
NOZEROCONF=yes
__EOT
done
## network : pre setup : 01 : end
## ----------------------------------------------



sed -i -e 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config


export http_proxy="http://10.110.103.250:18080/"
export ftp_proxy="http://10.110.103.250:18080/"
/bin/cat /proc/cmdline | sed 's/ /\n/g' | grep ^myop_ > /tmp/boot_parameters
. /tmp/boot_parameters
mkdir -p /root/rpmbuild/SPECS
mkdir -p /root/rpmbuild/SOURCES
mkdir -p /root/rpmbuild/BUILDROOT
mkdir -p /root/rpmbuild/SRPMS
 
if [ ! -d /root/.ssh ]; then
  mkdir /root/.ssh
fi
chmod 700 /root/.ssh 




log_mesg "User: passwd, sudo"
## User/Group setup

wget "http://10.110.103.250/KS/S99useraccounts" -O /root/S99useraccounts
chmod +x /root/S99useraccounts
sh /root/S99useraccounts
log_mesg "--== $?:DONE S99useraccounts -----------------------------------"

wget "http://10.110.103.250/KS/vmdb0018-authorized_keys" -O /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
log_mesg "--== $?:DONE /root/.ssh/authorized_keys -----------------------------------"

log_mesg "setup rpm build on /root"
mkdir -p /usr/src/redhat/temp
cat >> /root/.rpmmacros << __EOF
%packager GMO System Div. <sys-int@gmo.jp>

%_tmppath %{_topdir}/temp
%_signature gpg
%_gpg_name __KEYID__
__EOF
log_mesg "--== $?:DONE /root/.rpmmacros -----------------------------------"



log_mesg "---------------------------------"
log_mesg "fstab mount setup"
mkdir -p /export/var
mkdir -p /kvm/libvirt
mkdir -p /libvirt
mkdir -p /xen

log_mesg "---------------------------------"


set -x -v
exec 1>/root/ks-post.log 2>&1

## wget "http://10.110.103.250/cblr/svc/op/yum/system/vn0c0353.apu8.internal-gmo" --output-document=/etc/yum.repos.d/cobbler-config.repo

# Start post install kernel options update
if [ -f /etc/default/grub ]; then
  TMP_GRUB=$(gawk 'match($0,/^GRUB_CMDLINE_LINUX="([^"]+)"/,a) {printf("%s\n",a[1])}' /etc/default/grub)
  sed -i '/^GRUB_CMDLINE_LINUX=/d' /etc/default/grub
  echo "GRUB_CMDLINE_LINUX=\"$TMP_GRUB notsc intel_idle.max_cstate=0 pcie_aspm=off max_loop=32 elevator=deadline splash biosdevname=0 netloop.nloopbacks=32 console=tty0 console=ttyS0,115200n8 \"" >> /etc/default/grub
  grub2-mkconfig -o /boot/grub2/grub.cfg
else
  /sbin/grubby --update-kernel=$(/sbin/grubby --default-kernel) --args="notsc intel_idle.max_cstate=0 pcie_aspm=off max_loop=32 elevator=deadline splash biosdevname=0 netloop.nloopbacks=32 console=tty0 console=ttyS0,115200n8 "
fi
# End post install kernel options update


## /boot/grub/grub.conf
## sed -i -e 's/ nomodeset//g' /boot/efi/EFI/redhat/grub.conf
sed -i -e 's/ nomodeset//g' /boot/grub/grub.conf

## sed -i -e 's/ console=ttyS1/ console=ttyS0/g' /boot/efi/EFI/redhat/grub.conf
sed -i -e 's/ console=ttyS1/ console=ttyS0/g' /boot/grub/grub.conf

## sed -i -e 's/serial --unit=1 /serial --unit=0 /g' /boot/efi/EFI/redhat/grub.conf
sed -i -e 's/serial --unit=1 /serial --unit=0 /g' /boot/grub/grub.conf

if [ `grep -c splashimage /boot/efi/EFI/redhat/grub.conf` -eq 0 ]; then
    if [ -f /boot/grub/grub.conf ]; then
        cat /etc/grub.conf | sed -e 's/serial console/serial console\n\nsplashimage=(hd0,0)\/boot\/grub\/splash.xpm.gz\n/g' > /root/next-grub.conf
        cat /root/next-grub.conf > /boot/grub/grub.conf
    elif [ -f /boot/efi/EFI/redhat/grub.conf ]; then
        cat /boot/efi/EFI/redhat/grub.conf | sed -e 's/serial console/serial console\n\nsplashimage=(hd0,1)\/boot\/grub\/splash.xpm.gz\n/g' > /root/next-grub.conf
        cat /root/next-grub.conf > /boot/efi/EFI/redhat/grub.conf
    fi
fi

cat > /etc/init/ttyS1.conf << __EOF
## ttyS1 - agetty
## This service maintains a agetty on ttyS1.

stop on runlevel [S016]
start on runlevel [235]

respawn
exec agetty -h -L -w /dev/ttyS1 115200 vt100-nav
__EOF

## ---------------------------------
## additional ttyS0 (COM0) console
cat > /etc/init/ttyS0.conf << __EOF
# ttyS0 - agetty
#
# This service maintains a agetty on ttyS0.

stop on runlevel [S016]
start on runlevel [235]

respawn
##exec agetty -h -L -w /dev/ttyS0 115200 vt102
exec agetty -h -L -w /dev/ttyS0 115200 vt100-nav
__EOF
## ---------------------------------

echo tty0 >> /etc/securetty
if [ `grep -c ttyS0 /etc/securetty` -eq 0 ]; then
  echo ttyS0 >> /etc/securetty
fi
if [ `grep -c ttyS1 /etc/securetty` -eq 0 ]; then
  echo ttyS1 >> /etc/securetty
fi
##
## Backup current network config
mkdir -p /etc/sysconfig/network-scripts/SPOOL
DIR_NW=/etc/sysconfig/network-scripts
DIR_SPOOL=/etc/sysconfig/network-scripts/SPOOL
NW_IF_LIST="lo eth0 eth1 eth2 eth3 usb0"
if [ -f /etc/sysconfig/network ]; then
  cp -avf /etc/sysconfig/network $DIR_SPOOL/network
fi
for anif in `echo "$NW_IF_LIST"`;
do
  if [ -f $DIR_NW/ifcfg-$anif ]; then
    cp -avf $DIR_NW/ifcfg-$anif $DIR_SPOOL/ifcfg-$anif
  fi
  if [ -f $DIR_NW/route-$anif ]; then
    cp -avf $DIR_NW/route-$anif $DIR_SPOOL/route-$anif
  fi
done

## hosts
log_mesg "hosts"
cat >> /etc/hosts << __EOF_HOSTS


10.110.103.250    el6sg-u8.apyz-inet

172.20.29.220	master01.apyz.internal-gmo	master01
172.20.43.220	master02.apyz.internal-gmo	master02
172.20.51.220	master03.apyz.internal-gmo	master03
172.20.59.220	master04.apyz.internal-gmo	master04
172.20.103.220	master05.apyz.internal-gmo	master05
172.20.143.220	master06.apyz.internal-gmo	master06
172.20.159.220	master07.apyz.internal-gmo	master07
172.20.183.220	master08.apyz.internal-gmo	master08
172.20.75.220	master12.apyz.internal-gmo	master12

__EOF_HOSTS

## ----------------------------------------------
## network : csv setup : 02 : start
##
## My Host Configration
## host_csv_file='iso-setup-vm0a-csv.txt'
host_csv_file='iso-setup-vn2c-csv.txt'

##
if [ -f /dev/shm/iso-setup-vn2c-csv.txt ]; then
  cp -avf /dev/shm/iso-setup-vn2c-csv.txt /root/
elif [ -f /tmp/iso-setup-vn2c-csv.txt ]; then
  cp -avf /tmp/iso-setup-vn2c-csv.txt /root/
elif [ -f /var/tmp/iso-setup-vn2c-csv.txt ]; then
  cp -avf /var/tmp/iso-setup-vn2c-csv.txt /root/
  sleep 12
fi
while : ; do
    sleep 10
    if [ -f /root/iso-setup-vn2c-csv.txt ]; then
        ls -l /root/iso-setup-vn2c-csv.txt
        logger "system setup host list file check"
        break
    fi
done &
if [ -f /dev/shm/iso-setup-unit-info.txt ]; then
  cp -avf /dev/shm/iso-setup-unit-info.txt /root/
elif [ -f /tmp/iso-setup-unit-info.txt ]; then
  cp -avf /tmp/iso-setup-unit-info.txt /root/
elif [ -f /var/tmp/iso-setup-unit-info.txt ]; then
  cp -avf /var/tmp/iso-setup-unit-info.txt /root/
  sleep 12
fi
##
df  > /root/info-df
## ls -l /data/ > /root/info-dir-data
ls -l /tmp/ > /root/info-tmp
ls -l /var/tmp/ > /root/info-var-tmp

## network : csv setup : 02 : end
## ----------------------------------------------

myip=0.0.0.0
myhostname="vm0a7999.apyz.internal-gmo"

proxy_host="10.110.103.250"

ip addr show eth0 | grep 'link/ether ' > /var/tmp/info-eth0
ip addr show eth0 | grep "global eth0" | awk '{print $2}' > /var/tmp/info-ip-eth0

cat /var/tmp/info-eth0 | awk '{print $2 }' | sed -e 's/://g' > /var/tmp/info-eth0-mac
cat /var/tmp/info-eth0 | awk '{print $2 }' > /var/tmp/info-eth0-mac-base

## DHCP MacAddr / MacAddr_base
## macaddr=` /sbin/ip addr show eth0  |/usr/bin/awk '/link\/ether/{ gsub(/:/,""); print $2 }' `
macaddr=`cat /var/tmp/info-eth0-mac`
macaddr_base=`cat /var/tmp/info-eth0-mac-base`

## Manage IP : myip
##myip=` cat ${host_csv_file} | grep -i ${macaddr} |cut -f17 -d'|' `
myip_cnt=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f13 -d'|' | wc -l`
myip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f13 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  myip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f13 -d'|' `
fi

## IMM IP : imm_ip
imm_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f2 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  imm_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f2 -d'|' `
fi
imm_ip_d4=`echo ${imm_ip} | cut -f4 -d'.'`
imm_ip_d3=`echo ${imm_ip} | cut -f3 -d'.'`
imm_ip_d2=`echo ${imm_ip} | cut -f2 -d'.'`
imm_ip_d1=`echo ${imm_ip} | cut -f1 -d'.'`

## DHCP IP : dhcp_ip
## dhcp_ip=`cat /var/tmp/info-ip-eth0 | cut -d'/' -f1`
dhcp_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f17 -d'|' `
if [ $myip_cnt -eq 0 ]; then
  dhcp_ip=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f17 -d'|' `
fi

## admin file url : admin_file_url
admin_file_url="http://10.110.103.250/admin/${imm_ip_d4}/${imm_ip_d3}/admin-${imm_ip_d1}-${imm_ip_d2}-${imm_ip_d3}-${imm_ip_d4}.txt"

## [root@el6sg08 setup]# cat iso-setup-unit-info.txt  | grep MAN_GW_IP | cut -d'|' -f2
## 172.20.176.1
DEF_GW_IP=` cat /data/iso-setup-unit-info.txt  | grep MAN_GW_IP | cut -d'|' -f2 `
MAN_NETMASK=` cat /data/iso-setup-unit-info.txt  | grep MAN_NETMASK | cut -d'|' -f2 `

## HostName : myhostname
if [ ${myip} != '0.0.0.0' ];then
##myhostname=` cat ${host_csv_file} | grep -i ${macaddr} |cut -f16 -d'|' `
myhostname=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f12 -d'|' `
## myhost data
cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr} |cut -f12 -d'|' > /root/myhost-data.txt
if [ $myip_cnt -eq 0 ]; then
  myhostname=` cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f12 -d'|' `
  ## myhost data
  cat /root/iso-setup-vn2c-csv.txt | grep -i ${macaddr_base} |cut -f12 -d'|' > /root/myhost-data.txt
fi

# [root@el6sg-u8 setup]# cat iso-setup-vn2c-csv.txt  | awk -F'|' '{print $16,$17,$18,$19,$20}' | grep vn2c
# vn2c0021.apu8-int 10.110.98.97 10.110.122.97 10.110.130.97 10.110.138.97
br_dhcp_ip="${dhcp_ip}"
br_544_ip="${myip}"
br_545_ip=`grep ${myhostname} /root/iso-setup-vn2c-csv.txt | cut -d'|' -f18`
br_546_ip=`grep ${myhostname} /root/iso-setup-vn2c-csv.txt | cut -d'|' -f19`
br_547_ip=`grep ${myhostname} /root/iso-setup-vn2c-csv.txt | cut -d'|' -f20`

eth0_mac_hw_addr=`grep ${myhostname} /root/iso-setup-vn2c-csv.txt | cut -d'|' -f9 | tr 'a-z' 'A-Z'`
if [ `echo ${eth0_mac_hw_addr} | grep -c ':'` -eq 0 ]; then
  mac_d1=`echo ${eth0_mac_hw_addr} | cut -c1-2`
  mac_d2=`echo ${eth0_mac_hw_addr} | cut -c3-4`
  mac_d3=`echo ${eth0_mac_hw_addr} | cut -c5-6`
  mac_d4=`echo ${eth0_mac_hw_addr} | cut -c7-8`
  mac_d5=`echo ${eth0_mac_hw_addr} | cut -c9-10`
  mac_d6=`echo ${eth0_mac_hw_addr} | cut -c11-12`
  eth0_mac_hw_addr="${mac_d1}:${mac_d2}:${mac_d3}:${mac_d4}:${mac_d5}:${mac_d6}"
fi
eth1_mac_hw_addr=`grep ${myhostname} /root/iso-setup-vn2c-csv.txt | cut -d'|' -f10 | tr 'a-z' 'A-Z'`
if [ `echo ${eth1_mac_hw_addr} | grep -c ':'` -eq 0 ]; then
  mac_d1=`echo ${eth1_mac_hw_addr} | cut -c1-2`
  mac_d2=`echo ${eth1_mac_hw_addr} | cut -c3-4`
  mac_d3=`echo ${eth1_mac_hw_addr} | cut -c5-6`
  mac_d4=`echo ${eth1_mac_hw_addr} | cut -c7-8`
  mac_d5=`echo ${eth1_mac_hw_addr} | cut -c9-10`
  mac_d6=`echo ${eth1_mac_hw_addr} | cut -c11-12`
  eth1_mac_hw_addr="${mac_d1}:${mac_d2}:${mac_d3}:${mac_d4}:${mac_d5}:${mac_d6}"
fi
#
TARGET=/etc/sysconfig/network-scripts/ifcfg-br0.544
sed -i 's/BOOTPROTO=none/BOOTPROTO=static/' ${TARGET}
cat >> ${TARGET} << EOT
NETMASK=${MAN_NETMASK}
IPADDR=${myip}
EOT
fi
##
TARGET=/etc/sysconfig/network
cat > ${TARGET} << __NET_EOT
NETWORKING=yes
HOSTNAME=${myhostname}
NOZEROCONF=yes
GATEWAY=${DEF_GW_IP}
__NET_EOT
##
##

if [ -f /etc/ntp.conf ]; then
cp /etc/ntp.conf /etc/ntp.conf.ORIG
cat /etc/ntp.conf.ORIG \
  | sed -e '/server 0.rhel.pool.ntp.org/i server ntp1.gmo.jp' \
  | sed -e '/server 0.centos.pool.ntp.org/i server ntp1.gmo.jp' \
  | sed -e '/.org$/d' > /etc/ntp.conf
fi

## ntpdate -u -v 192.168.253.240
ntpdate -u -v ntp1.gmo.jp

## resolv.conf
log_mesg "resolv.conf"
cat > /etc/resolv.conf << __EOF_RESOLV_CONF
search internal-gmo
nameserver 172.16.5.174
nameserver 192.168.1.194

__EOF_RESOLV_CONF
## nameserver 10.110.11.250


## log_mesg "  admin file url : http://10.110.103.250/admin/53/106/admin-10-110-106-53.txt"
log_mesg "  admin file url : ${admin_file_url}"
if [ ! -d /opt/admin ]; then
  mkdir -p /opt/admin
fi
/usr/bin/wget "${admin_file_url}" -O /opt/admin/admin-file.txt
test -f /root/iso-setup-unit-info.txt && cat /root/iso-setup-unit-info.txt >> /opt/admin/admin-file.txt
echo "flag_yum_update|true"         >> /opt/admin/admin-file.txt
echo "unit_vdx_bond_setup|false" >> /opt/admin/admin-file.txt
echo "unit_nexsus_bond_setup|true" >> /opt/admin/admin-file.txt
log_mesg "--== $?:DONE admin file -----------------------------------"


if [ `grep -c DHCP_GW_IP /opt/admin/admin-file.txt` -eq 1 ]; then
    grep '^DHCP_GW_IP' /opt/admin/admin-file.txt | awk -F'|' '{print $2}' > /tmp/gw
    grep '^MAN_GW_IP' /opt/admin/admin-file.txt | awk -F'|' '{print $2}' > /tmp/mangw

    GW_ADDR=`cat /tmp/gw`
    MAN_GW_ADDR=`cat /tmp/mangw`

    sed -i -e '/GATEWAY=/d' /etc/sysconfig/network
    echo "GATEWAY=$GW_ADDR" >> /etc/sysconfig/network

    route del default gw $MAN_GW_ADDR
    route add default gw $GW_ADDR

fi
log_mesg "--== $?:DONE ttyS0:/etc/securetty file -----------------------------------"

if [ -f /etc/sysconfig/libvirt-guests ]; then
sed -i -e 's/#ON_BOOT=start/ON_BOOT=ignore/g' -e 's/#ON_SHUTDOWN=suspend/ON_SHUTDOWN=shutdown/g' /etc/sysconfig/libvirt-guests
else
wget "http://10.110.103.250/KS/host-node-etc-sysconfig-libvirt-guests" -O /root/host-node-etc-sysconfig-libvirt-guests
cp -avf /root/host-node-etc-sysconfig-libvirt-guests /etc/sysconfig/libvirt-guests
fi





/usr/bin/wget "http://10.110.103.250/KS/S982-EL6-ibm-asu-director-setup" -O /root/S98-ibm-asu-director-setup
chmod +x /root/S98-ibm-asu-director-setup
sh /root/S98-ibm-asu-director-setup 10.110.103.250 10.110.119.250 el6sg-u8
log_mesg "--== $?:DONE S98 -----------------------------------"


/usr/bin/wget "http://10.110.103.250/KS/S106-kernel-tune-setup-havana" -O /root/S106-kernel-tune-setup
chmod +x /root/S106-kernel-tune-setup
sh /root/S106-kernel-tune-setup
log_mesg "--== $?:DONE S106 -----------------------------------"




wget "http://10.110.103.250/KS/304-netconfig-fix-usb0.sh" -O /root/304-netconfig-fix-usb0.sh
chmod +x /root/304-netconfig-fix-usb0.sh
sh /root/304-netconfig-fix-usb0.sh
log_mesg "--== $?:DONE 304 netconfig fix usb0 -----------------------------------"

wget "http://10.110.103.250/KS/S305-fix-usb0.sh" -O /root/S305-fix-usb0.sh
chmod +x /root/S305-fix-usb0.sh
cd /etc/rc3.d
ln -s /root/S305-fix-usb0.sh /etc/rc3.d/S99z305-fix-usb0.sh
log_mesg "--== $?:DONE S305 S99z305 -----------------------------------"

## x3550m5
## eth0 dhcp
## eth1 manage static
## for x3550m5
##   DHCP NIC


cat > /root/fix_yum_update.sh <<'EOD_FIX_YUM'
#!/bin/sh

set -x
set -e

VERSION=6.7

echo 'exclude=*.i686' >> /etc/yum.conf

cd /etc/yum.repos.d
cp -avf CentOS-Base.repo{,.orig}
sed -i  's/$releasever/6.7/' CentOS-Base.repo
sed -i  "s/^mirrorlist/#mirrorlist/" CentOS-Base.repo
sed -i  "s/^#baseurl/baseurl/"       CentOS-Base.repo
sed -i  "s/mirror.centos.org\/centos/ns01.ovps.internal-gmo\/pub\/Linux\/centos/" CentOS-Base.repo
rm -rvf /var/cache/yum/*

EOD_FIX_YUM

##
chmod +x /root/fix_yum_update.sh
sh /root/fix_yum_update.sh


## included ; yum update
wget "http://10.110.103.250/KS/S99z92-selinux-conf.sh" -O /root/S99z92-selinux-conf.sh
chmod +x /root/S99z92-selinux-conf.sh
cd /etc/rc3.d
ln -s /root/S99z92-selinux-conf.sh /etc/rc3.d/S99z92-selinux-conf.sh
log_mesg "--== $?:DONE S99z92 -----------------------------------"

wget "http://10.110.103.250/KS/post_S10z95-u8-nic-to-bond0.sh" -O /root/post_S10z95-u8-nic-to-bond0.sh
chmod +x /root/post_S10z95-u8-nic-to-bond0.sh
log_mesg "--== $?:DONE S99z92 -----------------------------------"

## Service
log_mesg "-------------------------------------"
log_mesg "service setup : START"
SVC_LIST=""

SVC_LIST="$SVC_LIST cups:off "
SVC_LIST="$SVC_LIST isdn:off rawdevices:off"
SVC_LIST="$SVC_LIST cobblerd:off"
SVC_LIST="$SVC_LIST readahead_early:off readahead:off"
SVC_LIST="$SVC_LIST dnsmasq:off mrepo:off openais:off cman:off"
SVC_LIST="$SVC_LIST multipathd:off qdiskd:off gpm:off"
SVC_LIST="$SVC_LIST iptables:off ip6tables:off"
SVC_LIST="$SVC_LIST iscsi:off iscsid:off"
SVC_LIST="$SVC_LIST abrt-ccpp:off"
SVC_LIST="$SVC_LIST kdump:off snmptrapd:off gfs2:off"
SVC_LIST="$SVC_LIST gfs2:off mdmonitor:off"
SVC_LIST="$SVC_LIST microcode_ctl:off pcmcia:off"
SVC_LIST="$SVC_LIST funcd:off certmaster:off"
SVC_LIST="$SVC_LIST xfs:off cpuspeed:off "
SVC_LIST="$SVC_LIST virt-who:off ksm:off ksmtuned:off"

SVC_LIST="$SVC_LIST snmpd:on"
SVC_LIST="$SVC_LIST ntpd:on apmd:on acpid:on named:on nscd:on "
SVC_LIST="$SVC_LIST rsyslog:on "
SVC_LIST="$SVC_LIST sysstat:on"

SVC_LIST="$SVC_LIST haldaemon:on"
SVC_LIST="$SVC_LIST ipmi:on"
for line in `echo $SVC_LIST`
do
  svc=`echo $line | awk -F':' '{print $1}'`
  svc_flg=`echo $line | awk -F':' '{print $2}'`
  if [ -f /etc/init.d/$svc ]; then
    cmd_svc="/sbin/chkconfig $svc $svc_flg"
    log_mesg "$cmd_svc"
    eval $cmd_svc
  fi
done

log_mesg "service setup : END"
log_mesg "--== $?:DONE chkconfig -----------------------------------"

## Log file : func
if [ ! -d /var/log/func ]; then
  mkdir -p /var/log/func
fi
if [ -d /var/log/func ]; then
  /bin/touch /var/log/func/func.log
  /bin/touch /var/log/func/audit.log
fi

if [ -f /etc/libvirt/qemu/networks/autostart/default.xml ]; then
  rm -rvf /etc/libvirt/qemu/networks/autostart/default.xml
fi

## Netowrk GATEWAY=172.20.56.1
HOST_NAME=${myhostname}
HOST_NAME_STR=`grep "HOSTNAME" /etc/sysconfig/network | awk -F'=' '{print $2}'`
log_mesg "hostname : $HOST_NAME"
log_mesg "HOST_NAME_STR : $HOST_NAME_STR"
DEF_GATEWAY="${DEF_GW_IP}"
if [ `grep -c "capture" /etc/sysconfig/network` -eq 1 ]; then
    DEF_GATEWAY="${DEF_GW_IP}"
    echo "MTU=9000" >> /etc/sysconfig/network-scripts/ifcfg-eth3
fi
log_mesg "gateway setup : ${DEF_GATEWAY}"
grep -v GATEWAY /etc/sysconfig/network > /etc/sysconfig/network.tmp
echo "GATEWAY=${DEF_GATEWAY}" >> /etc/sysconfig/network.tmp
echo "NISDOMAIN=apyz.internal-gmo" >> /etc/sysconfig/network.tmp
rm -f /etc/sysconfig/network
mv /etc/sysconfig/network.tmp /etc/sysconfig/network

log_mesg "acpi setup : START"
cp -ip /etc/acpi/actions/power.sh /etc/acpi/actions/power.sh.original
sed -i -e 's/shutdown -h now/#shutdown -h now/g' /etc/acpi/actions/power.sh
echo "( echo "Push PowerButton was detect" | logger -p local7.warn -t "acpi/power.sh" )" >> /etc/acpi/actions/power.sh
log_mesg "acpi setup : END"

log_mesg "--== $?:DONE /etc/acpi/actions/power.sh -----------------------------------"



wget "http://10.110.103.250/KS/S117-raid-cli-manager-setup-el6-ce65.sh" -O /root/S117-raid-cli-manager-setup-el6.sh
sed -i -e 's/___COBBLER_HOST_IPADDR___/10.110.103.250/g' \
 -e 's/___COBBLER_HOST_MANAGE_IPADDR___/10.110.119.250/g' \
 -e 's/___COBBLER_HOST_URL_PATH___/el6sg-u8/g' \
  /root/S117-raid-cli-manager-setup-el6.sh
chmod +x /root/S117-raid-cli-manager-setup-el6.sh
sh /root/S117-raid-cli-manager-setup-el6.sh
log_mesg "--== $?:DONE S117 -----------------------------------"

wget "http://10.110.103.250/KS/005-megacli-IBM-x3650m2.pl" -O /root/005-megacli-IBM-x3650m2.pl
chmod +x /root/005-megacli-IBM-x3650m2.pl
log_mesg "--== $?:DONE 005 -----------------------------------"

wget "http://10.110.103.250/KS/905-megacli-x3550m3-writeback-only.sh" -O /root/905-megacli-x3550m3-writeback-only.sh
chmod +x /root/905-megacli-x3550m3-writeback-only.sh
sh /root/905-megacli-x3550m3-writeback-only.sh
log_mesg "--== $?:DONE 905 -----------------------------------"

wget "http://10.110.103.250/KS/997-megacli-PowerSave-none-setup_rm0a.sh" -O /root/997-megacli-PowerSave-none-setup_rm0a.sh
sed -i -e 's/___COBBLER_HOST_IPADDR___/10.110.103.250/g' /root/997-megacli-PowerSave-none-setup_rm0a.sh
chmod +x /root/997-megacli-PowerSave-none-setup_rm0a.sh
sh /root/997-megacli-PowerSave-none-setup_rm0a.sh
log_mesg "--== $?:DONE 997 -----------------------------------"

/usr/bin/wget "http://10.110.103.250/KS/set_nrpe_u2u3u4u5u6.sh" -O /root/set_nrpe_u2u3u4u5u6.sh
chmod +x /root/set_nrpe_u2u3u4u5u6.sh
bash /root/set_nrpe_u2u3u4u5u6.sh
log_mesg "--== $?:DONE /root/set_nrpe_u2u3u4u5u6.sh -----------------------------------"

## Message
echo "Linux Kickstart is COMPLETELY DONE." > /dev/console
echo "proxy=http://10.110.103.250:18080/" >> /etc/yum.conf


log_mesg "--post_network config START -------------------------------"
## Start post_install_network_config generated code

## we have bonded interfaces, so set max_bonds
if [ -f "/etc/modprobe.conf" ]; then
    echo "options bonding max_bonds=1" >> /etc/modprobe.conf
fi

## create a working directory for interface scripts
mkdir /etc/sysconfig/network-scripts/cobbler
cp /etc/sysconfig/network-scripts/ifcfg-lo /etc/sysconfig/network-scripts/cobbler/

## set the gateway in the network configuration file
grep -v GATEWAY /etc/sysconfig/network > /etc/sysconfig/network.cobbler
echo "GATEWAY=10.110.112.1" >> /etc/sysconfig/network.cobbler
mv -f /etc/sysconfig/network /var/tmp/old.etc.sysconfig.network
mv /etc/sysconfig/network.cobbler /etc/sysconfig/network

## set the hostname in the network configuration file
grep -v HOSTNAME /etc/sysconfig/network > /etc/sysconfig/network.cobbler
echo "HOSTNAME=${myhostname}" >> /etc/sysconfig/network.cobbler
mv -f /etc/sysconfig/network /var/tmp/old.etc.sysconfig.network
mv /etc/sysconfig/network.cobbler /etc/sysconfig/network

## Also set the hostname now, some applications require it
## (e.g.: if we're connecting to Puppet before a reboot).
/bin/hostname ${myhostname}

## # Start configuration for bond0.1501
## echo "DEVICE=bond0.1501" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "BRIDGE=br0.1501" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.1501
## # End configuration for bond0.1501
## 
## # Start configuration for bond0.2001
## echo "DEVICE=bond0.2001" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "BRIDGE=br0.2001" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.2001
## # End configuration for bond0.2001

## Start configuration for br0_dhcp
echo "DEVICE=br0_dhcp" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "ONBOOT=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "IPADDR=${br_dhcp_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
sed -i -e 's/^/##/g' /etc/sysconfig/network-scripts/cobbler/ifcfg-br0_dhcp
## End configuration for br0.544

## Start configuration for br0.544
echo "DEVICE=br0.544" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "IPADDR=${br_544_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.544
## End configuration for br0.544

## Start configuration for br0.545
echo "DEVICE=br0.545" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "IPADDR=${br_545_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.545
## End configuration for br0.545

## Start configuration for br0.546
echo "DEVICE=br0.546" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "IPADDR=${br_546_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.546
## End configuration for br0.546

## Start configuration for br0.547
echo "DEVICE=br0.547" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "IPADDR=${br_547_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.547
## End configuration for br0.547

## # Start configuration for br0.1501
## echo "DEVICE=br0.1501" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.1501
## # End configuration for br0.1501

## # Start configuration for br0.2001
## echo "DEVICE=br0.2001" > /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "TYPE=Bridge" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-br0.2001
## # End configuration for br0.2001

## Start configuration for bond0.545
echo "DEVICE=bond0.545" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "BRIDGE=br0.545" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.545
## End configuration for bond0.545

## Start configuration for bond0.546
echo "DEVICE=bond0.546" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "BRIDGE=br0.546" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.546
## End configuration for bond0.546

## Start configuration for bond0.547
echo "DEVICE=bond0.547" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "BRIDGE=br0.547" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.547
## End configuration for bond0.547

## Start configuration for bond0
echo "DEVICE=bond0" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
if [ -f "/etc/modprobe.conf" ]; then
    echo "alias bond0 bonding" >> /etc/modprobe.conf.cobbler
fi
cat >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0 << EOF
BONDING_OPTS="mode=4 miimon=100 lacp_rate=slow xmit_hash_policy=layer3+4"
EOF
echo "BRIDGE=br0_dhcp" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0
## End configuration for bond0

## Start configuration for bond0.544
echo "DEVICE=bond0.544" > /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "BRIDGE=br0.544" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "VLAN=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
echo "ONPARENT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-bond0.544
## End configuration for bond0.544

## Start configuration for eth1
echo "DEVICE=eth1" > /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "HWADDR=${eth1_mac_hw_addr}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
IFNAME=$(ip -o link | grep -i ${eth1_mac_hw_addr} | sed -e 's/^[0-9]*: //' -e 's/:.*//')
if [ -f "/etc/modprobe.conf" ] && [ $IFNAME ]; then
    grep $IFNAME /etc/modprobe.conf | sed "s/$IFNAME/eth1/" >> /etc/modprobe.conf.cobbler
    grep -v $IFNAME /etc/modprobe.conf >> /etc/modprobe.conf.new
    rm -f /etc/modprobe.conf
    mv /etc/modprobe.conf.new /etc/modprobe.conf
fi
echo "SLAVE=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "MASTER=bond0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "HOTPLUG=no" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth1
## End configuration for eth1

## Start configuration for eth0
echo "DEVICE=eth0" > /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "HWADDR=${eth0_mac_hw_addr}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
IFNAME=$(ip -o link | grep -i ${eth0_mac_hw_addr} | sed -e 's/^[0-9]*: //' -e 's/:.*//')
if [ -f "/etc/modprobe.conf" ] && [ $IFNAME ]; then
    grep $IFNAME /etc/modprobe.conf | sed "s/$IFNAME/eth0/" >> /etc/modprobe.conf.cobbler
    grep -v $IFNAME /etc/modprobe.conf >> /etc/modprobe.conf.new
    rm -f /etc/modprobe.conf
    mv /etc/modprobe.conf.new /etc/modprobe.conf
fi
echo "TYPE=Ethernet" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "IPADDR=${dhcp_ip}" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "NETMASK=255.255.248.0" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS1=10.110.103.250" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS2=172.16.5.174" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS3=192.168.1.194" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS4=210.157.0.11" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS5=210.157.0.1" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
echo "DNS6=210.157.0.2" >> /etc/sysconfig/network-scripts/cobbler/ifcfg-eth0
## End configuration for eth0

sed -i -e "/^nameserver /d" /etc/resolv.conf
echo "nameserver 10.110.103.250" >>/etc/resolv.conf
echo "nameserver 172.16.5.174" >>/etc/resolv.conf
echo "nameserver 192.168.1.194" >>/etc/resolv.conf
echo "nameserver 210.157.0.11" >>/etc/resolv.conf
echo "nameserver 210.157.0.1" >>/etc/resolv.conf
echo "nameserver 210.157.0.2" >>/etc/resolv.conf

sed -i 's/ONBOOT=yes/ONBOOT=no/g' /etc/sysconfig/network-scripts/ifcfg-eth*

mv -vf /etc/sysconfig/network-scripts/ifcfg-* /var/tmp/
## mv -vf /etc/sysconfig/network-scripts/cobbler/* /etc/sysconfig/network-scripts/
rsync -arv /etc/sysconfig/network-scripts/cobbler/ /etc/sysconfig/network-scripts/
mv -vf /etc/sysconfig/network-scripts/cobbler /var/tmp/
if [ -f "/etc/modprobe.conf" ]; then
cat /etc/modprobe.conf.cobbler >> /etc/modprobe.conf
rm -vf /etc/modprobe.conf.cobbler
fi
## End post_install_network_config generated code

log_mesg "--$?:post_network config END -------------------------------"


log_mesg "--download_config_files START -------------------------------"
## Start download cobbler managed config files (if applicable)
## End download cobbler managed config files (if applicable)

log_mesg "--$?:download_config_files END -------------------------------"
log_mesg "--cobbler_register START -------------------------------"
## Begin cobbler registration
## skipping for system-based installation
## End cobbler registration

log_mesg "--$?:cobbler_register END -------------------------------"
log_mesg "--post_anamon START -------------------------------"

log_mesg "--$?:post_anamon END -------------------------------"



## wget "http://10.110.103.250/cblr/svc/op/ks/system/vn0c0353.apu8.internal-gmo" -O /root/cobbler.ks
wget "http://10.110.103.250/cblr/svc/op/trig/mode/post/system/${myhostname}" -O /dev/null
log_mesg "--== $?:DONE final step -----------------------------------"
%end




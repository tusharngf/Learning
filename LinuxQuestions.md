# Learning


Process SLA.

Incident: 
P1 - Immediate response 4 hours resolution
P2 - Immediate response 12 hours resolution
P3 - Acknowledgement and 4 days resolution
P4 - Acknowledgement and 10 days resolution

Change management
Standard Change → new demand, modify cloud infra, low risk changes which are planned and carried out with specified SOPs
Normal Change → Patching, planned activity, maintenance, planned in advance, full range of assessments and authorizations, technical approval and the authorization of a CAB
Emergency Change → must be introduced as soon as possible, resolve a major incident or implement a security patch, replacement of failed hardware

Change planning: 
Change approval: 
Change implementation:
Change closure: 

Individual task will be created for all stakeholders and respective tasks will be assigned to respective teams Infra, app, db

For hardware replacement
https://www.inoc.com/blog/how-change-management-mitigates-risk-in-technology-support




Linux Booting Process

→ BIOS
Integriti checks
Search and load boot loader program
Search boot loader in HDD
BIOS gives control to boot loader
So, in simple terms BIOS loads and executes the MBR boot loader.
→ MBR
1st sector
512 byte - 446 primary boot loader info, 64 partition table info, 2 magic No.
MBR loads and executes the GRUB2 boot loader
-----
→ GRUB2
Rhel7 default boot loader is 2
/boot/grub2/grub.cfg
Grub searches and loads VMlinuz from /boot (compressed image of kernel) 
And extracts the contents of initramfs file temporary memory-based file system (tmpfs)
The initramfs (initial ram disk) acts as initial root file system mounts before real root file system mounts
----
The job of initramfs is supply drivers / modules such as for IDE, SCSI, or RAID, so that the root file system, on which those modules normally reside, can then be accessed and mounted
Dracut utility creates initramfs whenever a new kernel is installed
So, in simple terms GRUB2 just loads and executes Kernel and initramfs images.
----
→ Kernel
Central core
Its First program loaded in system startup 
Loads all kernel modules and from initrd.img
Loads 1st process systemd
Systemd process ID 1
----
→ Systemd
Initialize system & Loads all services
Systemd process reads the configuration file of /etc/systemd/system/default.target
Performs system initialization task defined by the system target 
Like below

Setting the hostname
Initializing the network
Initializing SELinux based on its configuration
Printing a welcome banner
Initializing the system hardware based on kernel boot arguments
Mounting the file systems, including virtual file systems such as the /proc file system
Starting swapping
systemd uses ‘targets’ instead of runlevels. 

By default, there are two main targets:
multi-user.target: analogous to runlevel 3
target: analogous to runlevel 5

Systemctl set-default graphical.target

More details
https://www.yoinsights.com/step-by-step-red-hat-enterprise-linux-7-booting-process/
====================================================

Grub error
Gets grub boot prompt in case grub.conf file missing from /boot/grub/grub.conf
Or /boot partition is corrupted
Solution
https://www.linuxsysadmins.com/grub-rescue-in-centos-and-rhel-7/


Multipathing

yum -y install device-mapper-multipath

defaults	system-level default configuration
blacklist	Blacklisted devies. Devices that should not be configured under DMMP
blacklist_exceptions	Exceptions to the blacklisted devices
devices	settings for individual storage controller devices
multipaths	fine-tune configuration of individual LUNs

User friendly names

defaults {
    user_friendly_names yes
}
--
multipaths {
    multipath {
            wwid     3600a0b8000473abc0000bafc52fac127  
            alias    mdisk001
              }
}

Rescan SCSI hosts
echo "- - -" > /sys/class/scsi_host/${host}/scan
echo "1" > /sys/class/fc_host/{host0/issue_lip
Not recommended it creates  (Loop Initialization Protocol (LIP) 
LIP is a bus reset, and causes device addition and removal.

multipath -v2 - refresh multipath and detect 
multipath -ll

If partitions created on multipath devices and that is not being listed, kpartx needs to be executed on the affected multipath devices.
# kpartx -a -v /dev/mapper/XXXXXXX

Remove LUN from server

Umount
vi /etc/multipath.conf
multipath -w 32a7d0050202a7d00000226
# multipath -ll
# multipath -f dm-35
Remove the devices got from “multipath -ll” or can find the device name from below location.
# ls -lthr /dev/disk/by-id/*226
# echo 1 > /sys/block/sdas/device/delete
# echo 1 > /sys/block/sdar/device/delete

To identify HBA adapter number

systool -c fc_host -v
or
ls /sys/class/fc_host
host0 host1

Get HBA details
lspci -nn | grep -i hba

Find WWN Number

cat /sys/class/fc_host/host0/node_name
0x20000000c9538d83
cat /sys/class/fc_host/host1/node_name
0x20000000c9538dac

Another way



To find the WWNs for the HBA ports :
# systool -c fc_host -v | grep port_name
    port_name           = "0x500143802426baf4"
    port_name           = "0x500143802426baf6"

Check Port state online or offline
more /sys/class/fc_host/host?/port_state

SCAN LUN Add in Multipath

https://www.thegeekdiary.com/how-to-scan-newly-assigned-luns-in-multipathd-under-centos-rhel/
https://www.2daygeek.com/scan-detect-luns-scsi-disks-on-redhat-centos-oracle-linux/
  


========================================








RAID
RAID 0 – striping - fast i/o, min 2 disks, no overhead, all capacity used
RAID 1 – mirroring - Data are stored twice by writing them to both the data drive, min 2 disks, if drive failed, controller uses other drive to continue operations, 
RAID 5 – striping with parity → min 3 drives but can work with up to 16
Advantages of RAID 5
Read data transactions are very fast while write data transactions are somewhat slower (due to the parity that has to be calculated).
If a drive fails, you still have access to all data, even while the failed drive is being replaced and the storage controller rebuilds the data on the new drive.

RAID 6 – striping with double parity - min 4 drives, 
RAID 10 – combining mirroring and striping
======
LVM

Lvreduce

Un-mount the filesystem 
# umount -v /mnt/tecmint_reduce_test/

Run e2fsck on the volume device - in case any error
# e2fsck -ff /dev/vg_tecmint_extra/tecmint_reduce_test

Reduce the Filesystem.(resize2fs)
# resize2fs /dev/vg_tecmint_extra/tecmint_reduce_test 10GB
 
Reduce the logical Volume(lvreduce)
# lvreduce -L -8G /dev/vg_tecmint_extra/tecmint_reduce_test

Mount the filesystem back for production.
--------------------------------------------------

Lvextend
When you want to mention size then L
For options like 100%FREE or extents we have to use small l
# lvextend -l +4607 /dev/vg_tecmint/LogVol01
Or
#lvresize -L +35g /dev/vg_test/lv_test
# resize2fs /dev/vg_tecmint/LogVol01


How do you find that what are the disks are used for  logical volume mirroring ? 
# lvs -a -o +devices

SCANNING FILE SYSTEM
pvscan -vv
vgscan -vv
lvscan -vv


 Migrating LVM Partitions to New Logical Volume (Drive)


#lvs - check which disk you want to remove

Check newly added disk is visible
#vgs -o+devices | grep vg

Create pv with newly added disk
# pvcreate /dev/sdb

Vgextend and add new PV into same VG
# vgextend VGNAME /dev/sdb
# vgs

LV extend in case you add disk to server

pvcreate /dev/sdd1 /dev/sde1 (physical)
vgextend tushat_vg /dev/sdd1 /dev/sde1 ( volume group extend)
 lvextend -l +100%FREE /dev/tushar_vg/tushar_lv Logical volume extend


  
 If in-case, we need to know more information about which devices are mapped, use the ‘dmsetup‘ dependency command.
# lvs -o+devices
# dmsetup deps /dev/vgname/lvname

In the above results, there is 1 dependencies (PV) or (Drives) and here 17 were listed. If you want to confirm look into the devices, which has major and minor number of drives that are attached.

Now do migration using mirroring. Migrate data from old to new device
# lvconvert -m 1 /dev/vg1/lv1 /dev/sdb
-m = mirror
1 = adding a single mirror

Above step will take time according to our data size.
# lvs -o+devices

Once done you can remove old disk from mirror
# lvconvert -m 0 /dev/vg1/lv1 /dev/sda

# lvs -o+devices
# dmsetup deps /dev/vg1/lv1
# ls -l /dev | grep sd

Here you can see now logical volume will be depends on new disk, compare major and minor number
Go and verify data then remove the old disk from VG
Vgreduce VGNAME /dev/sda
Another method is using pvmove

pvmove -n   /dev/vg1/lv1    /dev/vda     /dev/sdb

For more details check below link
https://www.casesup.com/category/knowledgebase/howtos/how-to-migrate-lvm-to-new-storage
https://www.tecmint.com/lvm-storage-migration/


Move a Volume Group from one system to another?

Unmount
# umount /mnt/design/users

Make VG Inactive, it will remove from kernel and prevent any further activity.
# vgchange -an design

Export it
#vgexport VGNAME

We can remove disk once machine shutdown and attach to new disk

Now scan it
# pvscan
# vgimport VGNAME (for LVM 2)
vgimport design /dev/sdb1 /dev/sdb2  (for LVM 1)

Make it active
# vgchange -ay VGNAME 

Mount the filesystem now
Mount /dev/VG/LV

https://access.redhat.com/solutions/4123


Recover deleted LVM

LVM backups are stored in /etc/lvm/archives
vgcfgrestore --list VolGroup --- > it will recovery file of lvm like below
/etc/lvm/archive/VolGroup_00000-304429941.vg

vgcfgrestore -f /etc/lvm/archive/VolGroup_00003-2103841493.vg VolGroup -> to restore
Lvchange -ay VThen make it active

For more details
https://linuxgurublog.wordpress.com/2017/09/14/how-to-recover-deleted-lvm-partitions/
https://www.golinuxcloud.com/recover-lvm2-partition-restore-vg-pv-metadata/


How to recover deleted LVM
https://www.thegeekdiary.com/how-to-recover-deleted-logical-volume-lv-in-lvm-using-vgcfgrestore/




Stickybit, SUID, GUID

Suid- run script as if the owner of the file is running that. Ex passwd command has sticky bit set so every user can execute it even though owner is root

GUID is same as suid only we can set it on group level

SUID

chmod 4555

SGUID
chmod 2555

Sticky bit
# chmod +t [path_to_directory]
or 
# chmod 1777 [path_to_directory]


-----------------------------

Hardening

Create tmp, /var/tmp /var/log separate partition
Secure temp
Nosuid,nodev,noexec
Set banners
Remove unwanted services
Enable NTP or chrony
Disable unsafe services like ftp and enable sftp instead
Enable iptables 
Enable loggins - rsyslogs
Ensure correct permission are set to configuration files like sshd_config
SSH Hardening
PermitRootLogin no
AllowGroups
PermitEmptyPasswords no
ClientAliveInterval 300 
ClientAliveCountMax 0
LoginGraceTime
Cat  /etc/login.defs 

PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 7
INACTIVE=30

Default umask is set

Password Policy

vi /etc/pam.d/system-auth

password  sufficient  pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=5
password   requisite   pam_cracklib.so try_first_pass retry=3 minlen=12 ucredit=-1
auth        required      pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
account required pam_tally2.so




Linux Rescue
Boot from DVD - RHEL7 having built in rescue image
Select Troubleshooting option
select the option Rescue a CentOS Linux system
Choose 1 to continue
OS will load in /mnt/sysimage
chroot /mnt/sysimage

Check if dev, proc, sys, /dev/shm mounted if not then mount it

mount -o bind /dev /mnt/sysimage/dev
mount -o bind /sys /mnt/sysimage/sys
mount -t proc /proc /mnt/sysimage/proc
mount -o bind /dev/shm /mnt/sysimage/dev/shm

Emergency Mode
Add the following parameter at the end of the linux16 line :
systemd.unit=emergency.target


Single User Mode
Use for fsck, reset root pass, failed to mount fstab disks, fail to boot normally

find the kernel line (starts with “linux16“), then change the argument ro to rw init=/sysroot/bin/sh

Press: Ctrl X
#chroot /sysroot/
Reset pass
touch /.autorelabel


kernel panic?
A kernel panic is one of several Linux boot issues. In basic terms, it is a situation when the kernel can't load properly and therefore the system fails to boot. During the boot process, the kernel doesn't load directly. Instead, initramfs loads in RAM, then it points to the kernel (vmlinuz), and then the operating system boots. If initramfs gets corrupted or deleted at this stage because of recent OS patching, updates, or other causes, then we face a kernel panic.
Why ?
If the initramfs file gets corrupted.
If initramfs is not created properly for the specified kernel. Every kernel version has its own corresponding initramfs.
If the installed kernel is not supported or not installed correctly.
If recent patches have some flaws.
If a module has been installed from online or another source, but the initrd image is not created with the latest installed module.
Boot into linux rescue and cd /boot, if no initramfs then we have to generate the one
#uname -r
#dracut -f <acut -finitrd-image> <kernal-version>

Or also can use mkinitrd command in case its already present

Or if you manage to boot from old kernel then you can simple remove and reinstall kernel by using yum
Article for more details https://www.redhat.com/sysadmin/linux-kernel-panic


Grub Rescue
Why?
Grub bootloader is Deleted, Misconfigured or corrupted
Resolution
grub> ls
grub> ls (hd0,msdos1)
ls (hd0,msdos1)/ --------------> It will show contents from /boot
no file system found
grub rescue> ls (hd0,msdos1)/grub2 ----> it will show contents from grub2/ dir
ext4: file system
set boot=(hd0,msdos1)
linux /boot/vmlinuz root=/dev/sda1
set prefix=(hd0,msdos1)/grub2 -----> set grub path
initrd (hd0,msdos1)/initramfs-3.10.0-957.el7.x86_64.img → mention initrd image 
And then reboot it
There is alternate way go to rescue mode and reinstall grub using below command
grub2-install /dev/sda


NFS server and RPC processes
/myshare diskless.example.com(rw,no_root_squash)
exportfs -r
Client
Showmount -e serverIP
mount -t serverX:/myshare /mnt/nfsexport


Difference between NFS 2 3 4
https://www.linvirtshell.com/2018/06/difference-between-nfsv2-nfsv3-and-nfs4.html
Only rpc.mountd and nfsd are required to be running for NFSv4.
starting the nfs-server process starts the NFS server and other RPC processes. RPC processes includes:
– rpc.statd : implements monitoring protocol (NSM) between NFS client and NFS server
– rpc.mountd : NFS mount daemon that implements the server side of the mount requests from NFSv3 clients.
– rpc.idmapd : Maps NFSv4 names and local UIDs and GIDs
– rpc.rquotad : provides user quota information for remote users.


Samba

yum install samba

/etc/samba/smb.conf
[myshare]
    path = /sharedpath
    writable = no
    valid users = fred, @management

run testparm to check if any error in smb.conf

useradd -s /sbin/nologin fred
smbpasswd -a fred

# systemctl start smb nmb
# systemctl enable smb nmb

Client Side

# mkdir /mnt/myshare
# mount -o username=fred //serverX/myshare /mnt/myshare
Password for fred@//serverX/myshare: centos




App Slowness / Server Slow
Top
Load average 1 min, 5 min, 15 min

wa: i/o wait - cpu is waiting for disk or network. Anything above 10% I/O wait should be considered high
us: consumed by user processes. - app, db, executables - see which process on top line
If one process - check if restart can help
If multiple process or single process which app/db team says normal - try to increase server config
sy: consumed by system processes.
id: how idle each CPU is.
Press 1 to get details

i/o wait high >> check swap usage >> Swapping a lot (using from swap cache) - check ram usage 
free -m - must be high
If low swap - means real io problem - try iotop / iostat

 iostat
Linux 2.6.32-100.28.5.el6.x86_64 (dev-db)       07/09/2011


avg-cpu:  %user   %nice %system %iowait  %steal   %idle
                     5.68    0.00    0.52         2.03      0.00     91.76

Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
sda             194.72      1096.66      1598.70 2719068704 3963827344
sda1            178.20       773.45      1329.09 1917686794 3295354888
sda2             16.51       323.19       269.61  801326686  668472456


iostat -c - CPU
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
                  0.12     0.01     1.47         1.98       0.00   96.42


iostat -d - disk
Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
sda               3.35       149.81        12.66    1086002      91746
dm-0              5.37       148.59        12.65    1077154      91728

iostat -p sda
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           0.11    0.01    1.44    1.92    0.00    96.52
Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
sda               3.32       148.52        12.55    1086002      91770
sda1              0.07         0.56         0.00       4120         18
sda2              3.22       147.79        12.55    1080650      91752

[root@tecmint ~]# vmstat -S M 1 5 → -S M means show in MB
procs -----------memory---------- ---swap-- -----io---- --system-- -----cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 0  0      0    346     53    476    0    0    95     8   42   55  0  2 96  2  0
 0  0      0    346     53    476    0    0     0     0   12   15  0  0 100  0  0
 0  0      0    346     53    476    0    0     0     0   32   62  0  0 100  0  0


If everything looks normal i/o wait low, idle time high

Check if app/db depends on something else which is causing slowness
Ex. nfs
If app is slow check DB node is any issue
Analyze with below command if process is waiting for something
lsof -t -i pid
strace
https://scoutapm.com/blog/slow_server_flow_chart

sar -u gives you info about all CPUs from midnight



sar -r, which give you that day’s memory usage:

The main thing to look for in RAM usage is %memused and %commit. A quick word about the %commit field: This field can show above 100% since the Linux kernel routinely overcommits RAM. If %commit is consistently over 100%, this result could be an indicator that the system needs more RAM.

sar -d, which gives you the disk I/O
The %util field is pretty self-explanatory: It’s the utilization of that device. The await field contains the amount of time the I/O spends in the scheduler.

sar -f /var/log/sa/filename
https://www.redhat.com/sysadmin/troubleshooting-slow-servers

There are ways to limit to process using 
Nice 19 is lowest priority -20 is highest priority
renice -n 15 -p 77982
cpulimit -l 50 -p 1234 → set limit to running process 
cpulimit -l 50 matho-primes 0 9999999999 > /dev/null & → launch process with limit
Cgroups 








RHEL 6 7 8 Difference

RHEL 6
RHEL 7
RHEL 8
Kernel 2.6.32-71
Kernel 3.10.0-123
Kernel 4.18
EXT4= 16TB
XFS= 500TB
XFS= 1024TB
chkconfig
systemctl
systemctl
Service command
systemctl
systemctl
ntp
Chrony & NTP
Chrony only
iptables
Firewalld (iptables in backend)
Firewalld, ( nftables in backend)
resize2fs
xfs_grow
xfs_grow
/etc/sysconfig/network
/etc/hostname hostnamectl
/etc/hostname hostnamectl
Rsyslog for logs
Rsyslog and journal
Rsyslog and journal


https://www.technicalmint.com/linux/difference-between-rhel6-rhel7-and-rhel8/

How to upgrade Redhat 6 to 7

https://docs.thousandeyes.com/product-documentation/global-vantage-points/enterprise-agents/managing/how-do-i-perform-an-in-place-upgrade-from-the-latest-rhel-6-to-the-latest-rhel-7







Passwd
Username or login name
Encrypted password
User ID
Group ID
User description
User’s home directory
User’s login shell


/etc/sudoers 

Username
Password encrypted password
Minimum : days user has to wait to change pass
Maximum : maximum no of days pass valid
Warn : warning
Inactive : days account expire after pass expiry
Expire : when account expired


Firewalld
firewall-cmd --permanent --zone=public --add-port=80/tcp
--add service
Firewall-cmd reload



ULimit
-f fsize - maximum filesize
Nofile -n  max no of open file
-u max user process
nproc - max number of processes
Maxlogins
virtual memory

student        hard    nproc           20
faculty         soft       nproc           20

DHCP
https://www.tecmint.com/install-dhcp-server-client-on-centos-ubuntu/

KDUMP
https://www.linuxtechi.com/how-to-enable-kdump-on-rhel-7-and-centos-7/

Shell Scripting

SED

Find and replace word
sed 's/rtkit/sdkit/g' /etc/passwd

Change word with specific line range, also you can mention line number
sed '30,40 s/version/story/g' myfile.txt




AWK

Print the lines which match the given pattern. 
$ awk '/manager/ {print}' employee.txt

Print 3rd field and separate with : 
cat passwd  |awk -F: '{print $3}'


Redhat Pacemaker Cluster
https://www.freenetst.it/tech/rh7cluster/

pcs
grub.conf removed
lvm removed how to recover

https://www.google.com/url?sa=t&source=web&rct=j&url=https://www.tecmint.com/view-yum-history-to-find-packages-info/amp/&ved=2ahUKEwif5-eI3b3zAhUSgtgFHSaOB9kQFnoECAUQAQ&usg=AOvVaw2K02qUCii8cjxFCIqrKSFD


Dell IDRACk 

How to collect TSR Logs from dell IDrack
Maintenance >> SupportAssist >> SupportAssistCollect >> Start Collecting and select locally option

Dell Servers PowerEdge R740 R720



HP ILO
HPE ProLiant BL460c Gen 8
HPE ProLiant DL380 G7

Ilo 3 4
Add users - change password
In network setting can set to status IP address (NIC and TCP IP option)
Can check - FAN Speed, Temperature , Power supplies, processors, 


Firmware upgrade : Download latest firmware from HP website >> extract it >> Go to ILP >> Administration >> ILO FIrmware >> Chose File >> upload file




PXE Boot
https://www.youtube.com/watch?v=eeYMMi5Hvg4















Ansible Sample playbooks
---
  - name: Playbook
    hosts: webservers
    become: yes
    become_user: root
    tasks:
      - name: ensure apache is at the latest version
        yum:
          name: httpd
          state: latest
      - name: ensure apache is running
        service:
          name: httpd
          state: started

https://www.middlewareinventory.com/blog/ansible-playbook-example/



Network related commands linux
https://www.tecmint.com/linux-network-configuration-and-troubleshooting-commands/


Kernel Parameters sysctl
https://linuxize.com/post/sysctl-command-in-linux/
Sysctl -a to check all kernel parameters
sysctl -w parameter=value -- > to modify kernel parameter
sysctl -w net.ipv4.ip_forward=1 >> /etc/sysctl.conf
Another way if doing same thing is 
echo 1 > /proc/sys/net/ipv4/ip_forward → do it directly in /proc/sys


Kernel Module location
/usr/lib/modules


Hardmount soft mount
Hard link soft link
Fsck on root
Nfsstat -s 
nfsiostat






YUM commands
>> yum check-update --security
It will check all security related package 
rpm -qa --last
>> yum update --security
Updates all security related packages and dependencies.

NAGIOS configuration file location
cfg_file=/usr/local/nagios/etc/hosts.cfg
cfg_file=/usr/local/nagios/etc/services.cfg
cfg_file=/usr/local/nagios/etc/commands.cfg


Optimizing server

PHP 7.4, including FastCGI Process Manager (FPM) that gives gigantic agility advantages.
Setup a Quick Reverse Proxy

Enable Caching
OpCode cache – This one is composed of results from previous page requests. It saves time for applications like  Magento or Drupal.
Memory cache – Memory cache stores parts of data created by applications in system memory.  When visitors request those parts, the server can provide the data  without any processing. This one is faster than OpCode cache and is best for large load-balanced websites.
HTTP cache – This one doesn’t go with parts of data.  Instead, HTTP cache stores the whole HTML page.  When the page is requested once again, it is easy and fast to serve. This is  ideal for high traffic web applications.
Application cache – When applications, like Magento or Drupal, storee prepared template files in the form of pages, it can significantly reduce process time.  With this,you can use application cache in conjunction with any of the earlier mentioned caches.
 
WHAT IS SAAS PAAS IAAS
SaaS
Google Workspace, Dropbox, Salesforce, Cisco WebEx, Concur, GoToMeeting
PaaS
AWS Elastic Beanstalk, Windows Azure, Heroku, Force.com, Google App Engine, Apache Stratos, OpenShift
IaaS
DigitalOcean, Linode, Rackspace, Amazon Web Services (AWS), Cisco Metapod, Microsoft Azure, Google Compute Engine (GCE)





User Modification commands
userdel -r spiderman ( to delete home/spiderman folder as well)

usermod -G superheros spiderman  (add user to group)

chgrp -R superheros spiderman (change group for username)

usermod --shell /sbin/nologin spiderman (change shell for user)

useradd -g superheros -s /bin/bash -c "Ironman" -m -d /home/ironman ironman (one line to add)

id ironman ( to check username parameters)
uid=1001(ironman) gid=1001(superheros) groups=1001(superheros)

/etc/login.defs for all UID GID and pass age info

usermod -aG wheel username (For adding user to wheelgroup)
useradd -ou 0 -g 0 john ( add user as root)
usermod -a -G root john ( add user to root group)





Q.How to set a username and password that never expires
Ans: chage -M -1 tester



[root@localhost ~]# chage -l tester
Last password change                                    : Jul 02, 2024
Password expires                                        : Aug 31, 2024
Password inactive                                       : never
Account expires                                         : never
Minimum number of days between password change          : 0
Maximum number of days between password change          : 60
Number of days of warning before password expires       : 7
[root@localhost ~]# chage -M -1 tester
[root@localhost ~]# chage -l tester
Last password change                                    : Jul 02, 2024
Password expires                                        : never
Password inactive                                       : never
Account expires                                         : never
Minimum number of days between password change          : 0
Maximum number of days between password change          : -1
Number of days of warning before password expires       : 7



# Linux-Cheatsheet

### Operations Deployment (25%)

#### Configure kernel parameters, persistent and non-persistent

- **`sysctl`**: 
	- Command to modify kernel parameters at runtime.  
  	- Commonly used in performance tuning and setting network-related parameters.
	```sh
	# View the current value of a kernel parameter
	sysctl net.ipv4.ip_forward
	
	# List all current kernel parameters and their values
	sysctl -a
	
	# Load settings from a specified configuration file
	sysctl -p /path/to/your/sysctl.conf
	```

- **`/etc/sysctl.conf`**: 
	- Configuration file for kernel parameters that are read at boot.  
  	- Used for setting persistent kernel parameter changes.
	```sh
	# Enable IP forwarding (persistently)
	# Add the following line to /etc/sysctl.conf
	net.ipv4.ip_forward = 1
	
	# Set the maximum number of open files (persistently)
	# Add the following line to /etc/sysctl.conf
	fs.file-max = 100000
	
	# Increase the size of the receive buffer (persistently)
	# Add the following line to /etc/sysctl.conf
	net.core.rmem_max = 16777216
	```

- **`sysctl -w`**: 
	- Option to set kernel parameters dynamically.  
  	- Typically used for temporary changes that don't require a reboot.
	```sh
	# Enable IP forwarding (non-persistently)
	sysctl -w net.ipv4.ip_forward=1
	
	# Set the maximum number of open files (non-persistently)
	sysctl -w fs.file-max=100000
	
	# Increase the size of the receive buffer (non-persistently)
	sysctl -w net.core.rmem_max=16777216
	```
- **`/etc/sysctl.d/`**: 
	- Directory for additional kernel parameter configuration files.  
  	- Used for organizing kernel parameter settings in a modular way.
	```sh
	# Enable IP forwarding (persistently)
	# Create a file /etc/sysctl.d/99-ipforward.conf with the following content
	net.ipv4.ip_forward = 1
	
	# Set the maximum number of open files (persistently)
	# Create a file /etc/sysctl.d/99-filemax.conf with the following content
	fs.file-max = 100000
	
	# Increase the size of the receive buffer (persistently)
	# Create a file /etc/sysctl.d/99-rmemmax.conf with the following content
	net.core.rmem_max = 16777216
	```

#### Diagnose, identify, manage, and troubleshoot processes and services

- **`ps`**: 
	- Displays information about active processes.  
  	- Used for process monitoring and management.
	```sh
	# List all processes currently running
	ps -e
	
	# Display detailed information about processes
	ps aux
	
	# Display processes for a specific user
	ps -u username
	
	# List processes in a tree format
	ps -e --forest
	```

- **`top`**: 
	- Interactive tool for real-time system monitoring.  
  	- Commonly used to observe system load and process activity.
	```sh
	# Start top to monitor system processes in real-time
	top
	
	# Start top with batch mode operation for logging purposes
	top -b
	
	# Display top output sorted by memory usage
	top -o %MEM
	
	# Display top output with only specific user processes
	top -u username
	```

- **`htop`**: 
	- Enhanced version of `top` with a more user-friendly interface.  
  	- Preferred by many for real-time process monitoring.
	```sh
	# Start htop to monitor system processes with an interactive UI
	htop
	
	# Start htop sorted by CPU usage
	htop --sort-key PERCENT_CPU
	
	# Display only processes of a specific user
	htop -u username
	
	# Filter processes by command name
	htop -p $(pgrep -d ',' process_name)
	```

- **`systemctl`**: 
	- Command to manage systemd services.  
  	- Used for starting, stopping, enabling, and checking the status of services.
	```sh
	# Check the status of a service
	systemctl status apache2
	
	# Start a service
	systemctl start apache2
	
	# Stop a service
	systemctl stop apache2
	
	# Enable a service to start on boot
	systemctl enable apache2
	
	# Reload systemd manager configuration
	systemctl daemon-reload
	```

- **`service`**: 
	- Legacy command to manage system services.  
  	- Often used on systems without systemd.
	```sh
	# Start a service
	service apache2 start
	
	# Stop a service
	service apache2 stop
	
	# Restart a service
	service apache2 restart
	
	# Check the status of a service
	service apache2 status
	```

- **`journalctl`**: 
	- Command to query and display messages from the systemd journal.  
  	- Essential for troubleshooting system and service issues.
	```sh
	# View the entire system journal
	journalctl
	
	# View journal logs for a specific service
	journalctl -u apache2
	
	# View logs since the last boot
	journalctl -b
	
	# Follow new journal entries in real-time
	journalctl -f
	```

- **`strace`**: 
	- Diagnostic tool to monitor system calls and signals.  
  	- Used for debugging and analyzing the behavior of applications.
	```sh
	# Trace system calls and signals of a command
	strace ls
	
	# Trace a running process by PID
	strace -p 1234
	
	# Save strace output to a file
	strace -o output.txt ls
	
	# Trace only file-related system calls
	strace -e trace=file ls
	```

- **`dmesg`**: 
	- Prints the message buffer of the kernel.  
  	- Useful for diagnosing hardware and boot issues.
	```sh
	# Print the kernel ring buffer messages
	dmesg
	
	# View dmesg output in a less pager
	dmesg | less
	
	# Filter dmesg output for errors
	dmesg | grep -i error
	
	# Clear the kernel ring buffer
	dmesg -C
	```

- **`kill`**: 
	- Sends a signal to a process, usually to terminate it.  
  	- Used to stop processes manually.
	```sh
	# Kill a process by PID
	kill 1234
	
	# Send a specific signal to a process
	kill -9 1234
	
	# Kill all processes with a specific name
	pkill -f process_name
	
	# List available signals
	kill -l
	```

- **`pkill`**: 
	- Sends a signal to processes based on name and other attributes.  
  	- Useful for terminating multiple processes matching certain criteria.
	```sh
	# Kill processes by name
	pkill apache2
	
	# Send a specific signal to processes by name
	pkill -9 apache2
	
	# Kill processes owned by a specific user
	pkill -u username
	
	# Kill processes matching a pattern
	pkill -f pattern
	```

- **`pgrep`**: 
	- Searches for processes based on name and other attributes.  
  	- Helps in finding process IDs matching specific patterns.
	```sh
	# List process IDs by name
	pgrep apache2
	
	# List process IDs by name and user
	pgrep -u username apache2
	
	# List process IDs with full command matching
	pgrep -f pattern
	
	# List process IDs with extended regular expression
	pgrep -e pattern
	```

- **`pidof`**: 
	- Finds the process ID of a running program.  
  	- Commonly used to locate process IDs by program name.
	```sh
	# Get the PID of a running program
	pidof apache2
	
	# Get the PIDs of a running program with multiple instances
	pidof -x apache2
	
	# Get the PID of a running program with partial name match
	pidof -c partial_name
	```

- **`lsof`**: 
	- Lists open files and the processes that opened them.  
  	- Useful for troubleshooting file system and network issues.
	```sh
	# List all open files
	lsof
	
	# List open files by a specific process
	lsof -p 1234
	
	# List open files by a specific user
	lsof -u username
	
	# List open files by a specific network port
	lsof -i :80
	```

- **`netstat`**: 
	- Displays network connections, routing tables, interface statistics.  
  	- Used for network troubleshooting and monitoring.
	```sh
	# Display network connections, routing tables, interface statistics
	netstat -a
	
	# Display network connections with process information
	netstat -tpn
	
	# Display listening ports
	netstat -l
	
	# Display routing table
	netstat -r
	```

- **`ss`**: 
	- Utility to investigate sockets and connections.  
  	- Often used as a modern alternative to `netstat`.
	```sh
	# Display all sockets
	ss -a
	
	# Display listening sockets
	ss -l
	
	# Display TCP connections
	ss -t
	
	# Display UDP connections
	ss -u
	
	# Display summary statistics
	ss -s
	```

#### Manage or schedule jobs for executing commands

- **`cron`**: 
	- Daemon to execute scheduled commands.  
  	- Commonly used for recurring task automation.

- **`crontab`**: 
	- Command to manage cron job schedules.  
  	- Used to set up, edit, and list scheduled tasks.

- **`at`**: 
	- Schedules commands to run once at a specified time.  
  	- Useful for one-time task automation.

- **`batch`**: 
	- Queues commands to run when system load levels permit.  
  	- Used for batch processing during low system load.

- **`systemd timers`**: 
	- Timer units for scheduling tasks in systemd.  
  	- Preferred in systemd-based systems for task automation.

- **`anacron`**: 
	- Executes commands periodically with a frequency specified in days.  
  	- Used to ensure periodic tasks run even if the system was off.

#### Search for, install, validate, and maintain software packages or repositories

- **`yum`**: 
	- Package manager for RPM-based distributions.  
  	- Used for installing, updating, and removing packages.

- **`dnf`**: 
	- Next-generation package manager for RPM-based distributions.  
  	- Replaces `yum` with enhanced features and performance.

- **`apt`**: 
	- Package manager for Debian-based distributions.  
  	- Commonly used for managing .deb packages.

- **`rpm`**: 
	- Package manager for RPM packages.  
  	- Used for installing, querying, verifying, updating, and removing RPM packages.

- **`dpkg`**: 
	- Base package management system for Debian.  
  	- Used for low-level package operations.

- **`snap`**: 
	- Package manager for Snap packages.  
  	- Used for installing and managing containerized software packages.

- **`flatpak`**: 
	- Package manager for Flatpak packages.  
  	- Used for installing and running sandboxed desktop applications.

- **`zypper`**: 
	- Command line interface of ZYpp package manager for openSUSE.  
  	- Used for installing, updating, and managing software packages.

- **`pip`**: 
	- Package manager for Python packages.  
  	- Used to install and manage Python software libraries.

- **`gem`**: 
	- Package manager for Ruby packages.  
  	- Used to manage Ruby libraries (gems).

- **`apt-key`**: 
	- Manages keys for apt's trusted keyring.  
  	- Used to add and remove repository signing keys.

- **`yum-config-manager`**: 
	- Manages yum repository configuration.  
  	- Used to add, enable, and disable repositories.

- **`add-apt-repository`**: 
	- Adds a repository to the sources list.  
  	- Used to include additional software sources.

- **`update-rc.d`**: 
	- Updates System-V style init script links.  
  	- Used to manage service runlevels in Debian-based systems.

- **`systemctl enable/disable`**: 
	- Enables or disables a service to start at boot.  
  	- Used to manage service startup in systemd systems.

#### Recover from hardware, operating system, or filesystem failures

- **`fsck`**: 
	- Filesystem consistency check and repair.  
  	- Used to check and repair filesystem errors.

- **`e2fsck`**: 
	- Filesystem consistency check for ext2/ext3/ext4 filesystems.  
  	- Commonly used for checking and fixing ext filesystems.

- **`dd`**: 
	- Utility to convert and copy files at a low level.  
  	- Used for creating disk images and backups.

- **`smartctl`**: 
	- Controls and monitors storage devices using S.M.A.R.T.  
  	- Used for checking hard drive health.

- **`mdadm`**: 
	- Manages MD (multiple device) software RAID arrays.  
  	- Used for creating, assembling, and monitoring RAID arrays.

- **`dracut`**: 
	- Tool for generating initramfs images.  
  	- Used for creating initial ramdisk environments.

- **`initrd`**: 
	- Initial ramdisk used by the Linux kernel during boot.  
  	- Essential for loading necessary drivers before mounting the root filesystem.

- **`grub`**: 
	- GRand Unified Bootloader, manages boot configurations.  
  	- Used for bootloader management and configuration.

- **`rescue mode`**: 
	- Special boot mode for system recovery.  
  	- Used to troubleshoot and repair system boot issues.

- **`systemctl rescue`**: 
	- Boots the system into rescue mode using systemd.  
  	- Used for minimal system repair tasks.

#### Manage Virtual Machines (libvirt)

- **`virsh`**: 
	- Command-line interface for managing virtual machines via libvirt.  
  	- Used to create, control, and manage virtual machines.

- **`virt-install`**: 
	- Tool to create new virtual machines.  
  	- Used to automate the installation of new VMs.

- **`virt-manager`**: 
	- Graphical tool for managing virtual machines.  
  	- Provides an interface for managing VMs.

- **`virt-clone`**: 
	- Clones existing virtual machines.  
  	- Used to duplicate VMs with unique configurations.

- **`virt-sysprep`**: 
	- Prepares a virtual machine for cloning.  
  	- Cleans and resets VM configurations.

- **`qemu-img`**: 
	- Creates, converts, and modifies disk images.  
  	- Used for handling virtual machine disk images.

- **`libvirtd`**: 
	- Daemon for managing platform virtualization via libvirt.  
  	- Required for running and managing virtual machines.

- **`virsh list`**: 
	- Lists all active virtual machines.  
  	- Used for monitoring running VMs.

- **`virsh start/stop`**: 
	- Starts or stops a specified virtual machine.  
  	- Used for controlling VM states.

- **`virsh create/destroy`**: 
	- Creates or destroys a virtual machine instance.  
  	- Used for dynamic VM management.

#### Configure container engines, create and manage containers

- **`docker`**: 
	- Containerization platform for developing, shipping, and running applications.  
  	- Used for creating, managing, and running containers.

- **`podman`**: 
	- Daemonless container engine for managing OCI containers.  
  	- Used as a Docker alternative for container management.

- **`buildah`**: 
	- Tool for building OCI images.  
  	- Used for creating and managing container images.

- **`crictl`**: 
	- CLI for CRI-compatible container runtimes.  
  	- Used for interacting with container runtimes in Kubernetes environments.

- **`kubectl`**: 
	- CLI for Kubernetes cluster management.  
  	- Used for deploying, managing, and inspecting applications in Kubernetes.

- **`docker-compose`**: 
	- Tool for defining and running multi-container Docker applications.  
  	- Used for orchestrating multi-container deployments.

- **`docker build`**: 
	- Builds a Docker image from a Dockerfile.  
  	- Used for creating container images.

- **`docker run`**: 
	- Runs a command in a new Docker container.  
  	- Used for starting containers from images.

- **`docker ps`**: 
	- Lists running Docker containers.  
  	- Used for monitoring active containers.

- **

`docker images`**: 
	- Lists Docker images on the host.  
  	- Used for managing local container images.

- **`docker network`**: 
	- Manages Docker networks.  
  	- Used for creating and managing container networks.

- **`docker volume`**: 
	- Manages Docker volumes.  
  	- Used for handling persistent storage for containers.

- **`docker inspect`**: 
	- Displays detailed information about Docker objects.  
  	- Used for troubleshooting and examining containers.

- **`podman run`**: 
	- Runs a command in a new podman container.  
  	- Used similarly to `docker run` but without a daemon.

- **`podman ps`**: 
	- Lists running podman containers.  
  	- Used for monitoring podman-managed containers.

#### Create and enforce MAC using SELinux

- **`sestatus`**: 
	- Displays the current status of SELinux.  
  	- Used to check if SELinux is enabled and its current mode.

- **`getsebool`**: 
	- Retrieves the current setting of an SELinux boolean.  
  	- Used to query boolean values for SELinux policies.

- **`setsebool`**: 
	- Sets the current setting of an SELinux boolean.  
  	- Used to modify boolean values for policy tuning.

- **`semanage`**: 
	- Manages SELinux policy components.  
  	- Used for configuring SELinux policy settings.

- **`restorecon`**: 
	- Restores the default SELinux context for files.  
  	- Used to fix SELinux context issues on files.

- **`chcon`**: 
	- Changes the SELinux security context of a file.  
  	- Used for setting custom SELinux contexts.

- **`ls -Z`**: 
	- Lists files with their SELinux security context.  
  	- Used for viewing SELinux contexts of files.

- **`ps -Z`**: 
	- Displays process security contexts.  
  	- Used to check SELinux contexts of running processes.

- **`audit2allow`**: 
	- Generates SELinux policy allow rules from logs.  
  	- Used to create custom SELinux rules based on audit logs.

- **`ausearch`**: 
	- Searches the audit logs based on specified criteria.  
  	- Used for querying SELinux audit logs.

- **`/etc/selinux/config`**: 
	- Configuration file for SELinux settings.  
  	- Used for setting SELinux modes and policies.

- **`semodule`**: 
	- Manages SELinux policy modules.  
  	- Used to install and manage SELinux policy modules.

- **`setenforce`**: 
	- Switches SELinux between enforcing and permissive modes.  
  	- Used to temporarily change the enforcement mode of SELinux.

### Networking (25%)

#### Configure IPv4 and IPv6 networking and hostname resolution

- **`ip`**: 
	- Command for managing network interfaces and routes.  
  	- Used for configuring IP addresses, routes, and tunnels.

- **`ifconfig`**: 
	- Legacy tool for configuring network interfaces.  
  	- Often replaced by `ip` but still used in some scripts and systems.

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for managing network connections and devices.

- **`nmtui`**: 
	- Text user interface for NetworkManager.  
  	- Provides a simpler interface for managing network settings.

- **`hostnamectl`**: 
	- Controls the system hostname.  
  	- Used for setting the system's hostname and related settings.

- **`systemctl restart network`**: 
	- Restarts the network service.  
  	- Used to apply network configuration changes.

- **`/etc/hosts`**: 
	- Static table lookup for hostnames.  
  	- Used for local hostname resolution.

- **`/etc/resolv.conf`**: 
	- Configuration file for DNS resolution.  
  	- Used for setting DNS servers and search domains.

- **`ping`**: 
	- Sends ICMP ECHO_REQUEST to network hosts.  
  	- Used for checking network connectivity.

- **`traceroute`**: 
	- Traces the route packets take to a network host.  
  	- Used for diagnosing network path issues.

- **`netplan`**: 
	- Network configuration tool for Ubuntu.  
  	- Used for configuring network settings via YAML files.

#### Set and synchronize system time using time servers

- **`timedatectl`**: 
	- Command to query and change the system clock and its settings.  
  	- Used for managing system time and synchronization.

- **`ntpdate`**: 
	- Synchronizes the system clock with NTP servers.  
  	- Used for one-time clock synchronization.

- **`chronyc`**: 
	- Command-line interface for the chrony NTP client.  
  	- Used for managing and monitoring chrony.

- **`chronyd`**: 
	- Daemon for the chrony NTP client.  
  	- Used for maintaining accurate system time.

- **`systemctl restart chronyd`**: 
	- Restarts the chrony daemon.  
  	- Used to apply chrony configuration changes.

#### Monitor and troubleshoot networking

- **`netstat`**: 
	- Displays network connections, routing tables, and interface statistics.  
  	- Used for network troubleshooting and monitoring.

- **`ss`**: 
	- Investigates sockets and network connections.  
  	- Modern alternative to `netstat`.

- **`tcpdump`**: 
	- Network packet analyzer.  
  	- Used for capturing and analyzing network traffic.

- **`wireshark`**: 
	- Network protocol analyzer with a graphical interface.  
  	- Used for in-depth network traffic analysis.

- **`iftop`**: 
	- Displays bandwidth usage on an interface.  
  	- Used for monitoring network traffic in real-time.

- **`nmap`**: 
	- Network scanner to discover hosts and services.  
  	- Used for network discovery and security auditing.

- **`ping`**: 
	- Checks network connectivity by sending ICMP ECHO_REQUEST packets.  
  	- Commonly used to test if a host is reachable.

- **`traceroute`**: 
	- Traces the path packets take to reach a host.  
  	- Used for diagnosing network path issues.

- **`mtr`**: 
	- Combines the functionality of `ping` and `traceroute`.  
  	- Used for network diagnostic purposes.

- **`dig`**: 
	- DNS lookup utility.  
  	- Used for querying DNS name servers.

- **`nslookup`**: 
	- Queries DNS to obtain domain name or IP address mapping.  
  	- Used for DNS troubleshooting.

- **`ethtool`**: 
	- Displays and modifies network interface parameters.  
  	- Used for managing Ethernet devices.

- **`ip route`**: 
	- Shows/manages the IP routing table.  
  	- Used for configuring network routes.

- **`ip link`**: 
	- Manages and displays network interfaces.  
  	- Used for configuring network interfaces.

#### Configure the OpenSSH server and client

- **`sshd`**: 
	- Secure Shell daemon.  
  	- Provides secure encrypted communications between hosts.

- **`sshd_config`**: 
	- Configuration file for the OpenSSH server.  
  	- Used to set SSH server options.

- **`ssh`**: 
	- Secure Shell client.  
  	- Used to connect to SSH servers.

- **`ssh-keygen`**: 
	- Generates, manages, and converts authentication keys for SSH.  
  	- Used for creating SSH key pairs.

- **`scp`**: 
	- Secure copy program.  
  	- Used for copying files over SSH.

- **`sftp`**: 
	- Secure file transfer program.  
  	- Used for transferring files over SSH.

- **`systemctl restart sshd`**: 
	- Restarts the SSH daemon.  
  	- Used to apply SSH server configuration changes.

#### Configure packet filtering, port redirection, and NAT

- **`iptables`**: 
	- Utility for configuring Linux kernel firewall implemented in netfilter.  
  	- Used for setting up, maintaining, and inspecting firewall rules.

- **`firewalld`**: 
	- Dynamic firewall management tool with D-Bus interface.  
  	- Used for managing firewall rules in a more user-friendly way.

- **`nftables`**: 
	- Replaces iptables as the Linux firewall utility.  
  	- Used for managing firewall rules with better performance and flexibility.

- **`ufw`**: 
	- Uncomplicated Firewall, front-end for iptables.  
  	- Used for managing firewall rules easily.

- **`ip6tables`**: 
	- IPv6 version of iptables.  
  	- Used for managing IPv6 firewall rules.

- **`iptables-save`**: 
	- Saves the current iptables rules.  
  	- Used for exporting firewall rules to a file.

- **`iptables-restore`**: 
	- Restores iptables rules from a file.  
  	- Used for importing firewall rules from a file.

- **`firewall-cmd`**: 
	- Command-line interface for firewalld.  
  	- Used for managing firewalld configurations.

#### Configure static routing

- **`ip route`**: 
	- Command to show/manages the IP routing table.  
  	- Used for configuring static routes.

- **`route`**: 
	- Legacy command to show and manipulate the IP routing table.  
  	- Often replaced by `ip route`.

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for configuring static routes via NetworkManager.

- **`network-scripts`**: 
	- Scripts for network configuration in older Linux distributions.  
  	- Used for configuring network interfaces and routes.

- **`/etc/sysconfig/network-scripts/route-<interface>`**: 
	- Configuration file for static routes in Red Hat-based systems.  
  	- Used for setting persistent static routes.

#### Configure bridge and bonding devices

- **`brctl`**: 
	- Utility for configuring Ethernet bridge devices.  
  	- Used for creating and managing network bridges.

- **`ip link`**: 
	- Command to manage and display network interfaces.  
  	- Used for configuring network bonding and bridging.

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for configuring bonding and bridging via NetworkManager.

- **`teamd`**: 
	- Daemon to manage team network devices.  
  	- Used for creating and managing

 network teams (bonding).

- **`bonding`**: 
	- Linux kernel module for bonding multiple network interfaces.  
  	- Used for network interface bonding to increase throughput and redundancy.

#### Implement reverse proxies and load balancers

- **`nginx`**: 
	- Web server and reverse proxy server.  
  	- Used for load balancing and reverse proxying HTTP and other protocols.

- **`haproxy`**: 
	- High Availability Proxy, provides load balancing and high availability.  
  	- Used for distributing network traffic across multiple servers.

- **`apache mod_proxy`**: 
	- Apache module for proxy/gateway functionality.  
  	- Used for reverse proxying with the Apache web server.

- **`varnish`**: 
	- HTTP accelerator and reverse proxy.  
  	- Used for caching and load balancing HTTP traffic.

- **`squid`**: 
	- Caching and forwarding HTTP proxy.  
  	- Used for caching web traffic and implementing reverse proxies.

### Storage (20%)

#### Configure and manage LVM storage

- **`lvcreate`**: 
	- Creates a logical volume.  
  	- Used for creating new LVM logical volumes.

- **`vgcreate`**: 
	- Creates a volume group.  
  	- Used for creating new LVM volume groups.

- **`pvcreate`**: 
	- Prepares a physical volume for use by LVM.  
  	- Used for initializing physical storage devices.

- **`lvextend`**: 
	- Extends the size of a logical volume.  
  	- Used for increasing storage capacity of an LVM logical volume.

- **`vgreduce`**: 
	- Removes physical volumes from a volume group.  
  	- Used for reducing the size of a volume group.

- **`pvmove`**: 
	- Moves physical extents from one physical volume to another.  
  	- Used for balancing storage or replacing disks.

- **`vgextend`**: 
	- Adds physical volumes to a volume group.  
  	- Used for expanding the storage pool of a volume group.

- **`lvremove`**: 
	- Removes a logical volume.  
  	- Used for deleting LVM logical volumes.

- **`lvresize`**: 
	- Resizes a logical volume.  
  	- Used for adjusting the size of an LVM logical volume.

- **`vgremove`**: 
	- Removes a volume group.  
  	- Used for deleting LVM volume groups.

- **`pvremove`**: 
	- Removes a physical volume.  
  	- Used for decommissioning physical storage devices from LVM.

- **`lvdisplay`**: 
	- Displays information about logical volumes.  
  	- Used for viewing LVM logical volume details.

- **`vgdisplay`**: 
	- Displays information about volume groups.  
  	- Used for viewing LVM volume group details.

- **`pvdisplay`**: 
	- Displays information about physical volumes.  
  	- Used for viewing LVM physical volume details.

#### Manage and configure the virtual file system

- **`mount`**: 
	- Attaches a filesystem to the directory tree.  
  	- Used for mounting filesystems.

- **`umount`**: 
	- Detaches a filesystem from the directory tree.  
  	- Used for unmounting filesystems.

- **`fstab`**: 
	- Configuration file for static filesystem mounts.  
  	- Used for setting persistent mount points.

- **`/etc/fstab`**: 
	- Contains information about filesystems and their mount points.  
  	- Used for automating the mounting of filesystems at boot.

- **`/etc/mtab`**: 
	- Lists currently mounted filesystems.  
  	- Used for tracking active mounts.

- **`findmnt`**: 
	- Displays target mount point information.  
  	- Used for finding and displaying filesystem mount points.

- **`blkid`**: 
	- Displays or modifies block device attributes.  
  	- Used for querying block device information.

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for monitoring disk space usage.

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for checking disk usage of files and directories.

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing block device details.

- **`resize2fs`**: 
	- Resizes ext2/3/4 filesystems.  
  	- Used for expanding or shrinking ext filesystems.

- **`xfs_growfs`**: 
	- Expands an XFS filesystem.  
  	- Used for increasing the size of an XFS filesystem.

#### Create, manage, and troubleshoot filesystems

- **`mkfs`**: 
	- Builds a Linux filesystem on a device.  
  	- Used for creating new filesystems.

- **`mkfs.ext4`**: 
	- Creates an ext4 filesystem.  
  	- Commonly used for creating ext4 filesystems.

- **`mkfs.xfs`**: 
	- Creates an XFS filesystem.  
  	- Used for creating XFS filesystems.

- **`tune2fs`**: 
	- Adjusts tunable filesystem parameters on ext filesystems.  
  	- Used for modifying ext filesystem settings.

- **`fsck`**: 
	- Checks and repairs a Linux filesystem.  
  	- Used for filesystem integrity checks and repairs.

- **`e2fsck`**: 
	- Checks and repairs ext2/3/4 filesystems.  
  	- Used for ext filesystem maintenance.

- **`xfs_repair`**: 
	- Repairs an XFS filesystem.  
  	- Used for fixing issues in XFS filesystems.

- **`mount -o loop`**: 
	- Mounts a file as a filesystem.  
  	- Used for mounting disk image files.

#### Use remote filesystems and network block devices

- **`nfs`**: 
	- Network File System, allows remote file sharing.  
  	- Used for accessing files over a network.

- **`nfs-client`**: 
	- Mounts NFS shares on a client system.  
  	- Used for connecting to NFS shares.

- **`nfs-server`**: 
	- Exports directories over NFS.  
  	- Used for sharing directories over a network.

- **`mount.nfs`**: 
	- Mounts NFS filesystems.  
  	- Used for attaching NFS shares.

- **`/etc/exports`**: 
	- Configuration file for NFS exports.  
  	- Used for defining shared directories in NFS.

- **`autofs`**: 
	- Automounts filesystems on demand.  
  	- Used for automatically mounting remote filesystems.

- **`iscsiadm`**: 
	- Manages iSCSI initiator connections.  
  	- Used for connecting to iSCSI targets.

- **`targetcli`**: 
	- Configures iSCSI targets.  
  	- Used for managing iSCSI target configurations.

- **`mount.cifs`**: 
	- Mounts CIFS filesystems (Samba shares).  
  	- Used for accessing Windows shares.

- **`/etc/fstab`**: 
	- Used for automating the mounting of remote filesystems.  
  	- Contains entries for remote filesystem mounts.

#### Configure and manage swap space

- **`swapon`**: 
	- Enables devices and files for paging and swapping.  
  	- Used for activating swap space.

- **`swapoff`**: 
	- Disables devices and files for paging and swapping.  
  	- Used for deactivating swap space.

- **`mkswap`**: 
	- Sets up a Linux swap area.  
  	- Used for initializing swap space on a device.

- **`/etc/fstab`**: 
	- Contains entries for swap space.  
  	- Used for defining swap space to be activated at boot.

- **`free`**: 
	- Displays the amount of free and used memory in the system.  
  	- Used for monitoring memory and swap usage.

- **`vmstat`**: 
	- Reports virtual memory statistics.  
  	- Used for monitoring system performance and swap activity.

#### Configure filesystem automounters

- **`autofs`**: 
	- Service that automatically mounts filesystems.  
  	- Used for on-demand mounting of filesystems.

- **`/etc/auto.master`**: 
	- Master map for autofs.  
  	- Used for configuring automount points.

- **`/etc/auto.misc`**: 
	- Example automounter map file.  
  	- Used for defining specific automount configurations.

- **`automount`**: 
	- Command to reload the automounter.  
  	- Used for applying changes to autofs configurations.

#### Monitor storage performance

- **`iostat`**: 
	- Reports CPU and I/O statistics for devices and partitions.  
  	- Used for monitoring storage performance.

- **`iotop`**: 
	- Displays I/O usage by processes.  
  	- Used for identifying processes with high I/O activity.

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for checking available storage space.

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for identifying disk usage by files and directories.

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing storage device details.

- **`smartctl`**: 
	- Controls and monitors storage devices using S.M.A.R.T.  
  	- Used for checking the health of storage devices.

- **`blkid`**: 
	- Displays or modifies block device attributes.  
  	- Used for querying and setting block device metadata.

### Essential Commands (20%)

#### Basic Git Operations

- **`git clone`**: 
	- Clones a repository into a new directory.  
  	- Used for copying remote repositories locally.

- **`git commit`**: 
	- Records changes to the repository.  
  	- Used for saving snapshots of the project history.

- **`git pull`**: 
	- Fetches from and integrates with another repository.  
  	- Used for updating local repositories with remote changes.

- **`git push`**: 
	- Updates remote refs along with associated objects.  
  	- Used for sharing local changes with remote repositories.

- **`git branch`**: 
	- Lists, creates, or deletes branches.  
  	- Used for managing project branches.

- **`git checkout`**: 
	- Switches branches or restores working tree files.  
  	- Used for changing branches or reverting changes.

- **

`git merge`**: 
	- Joins two or more development histories together.  
  	- Used for combining changes from different branches.

- **`git status`**: 
	- Shows the working tree status.  
  	- Used for viewing the current state of the repository.

- **`git log`**: 
	- Shows the commit logs.  
  	- Used for reviewing project history.

- **`git diff`**: 
	- Shows changes between commits, commit and working tree, etc.  
  	- Used for comparing changes.

#### File management, archiving, and compression

- **`ls`**: 
	- Lists directory contents.  
  	- Used for viewing files and directories.

- **`cp`**: 
	- Copies files and directories.  
  	- Used for duplicating files and directories.

- **`mv`**: 
	- Moves or renames files and directories.  
  	- Used for relocating or renaming files and directories.

- **`rm`**: 
	- Removes files or directories.  
  	- Used for deleting files and directories.

- **`tar`**: 
	- Archives files.  
  	- Used for creating and extracting tar archives.

- **`gzip`**: 
	- Compresses or decompresses files.  
  	- Used for handling gzip compressed files.

- **`bzip2`**: 
	- Compresses or decompresses files.  
  	- Used for handling bzip2 compressed files.

- **`zip`**: 
	- Packages and compresses files.  
  	- Used for creating zip archives.

- **`unzip`**: 
	- Extracts files from a zip archive.  
  	- Used for unpacking zip files.

#### Text processing

- **`grep`**: 
	- Searches for patterns in files.  
  	- Used for finding specific text within files.

- **`awk`**: 
	- Pattern scanning and processing language.  
  	- Used for text processing and data extraction.

- **`sed`**: 
	- Stream editor for filtering and transforming text.  
  	- Used for text manipulation and editing.

- **`cut`**: 
	- Removes sections from each line of files.  
  	- Used for extracting parts of text files.

- **`sort`**: 
	- Sorts lines of text files.  
  	- Used for ordering text data.

- **`uniq`**: 
	- Reports or omits repeated lines.  
  	- Used for finding unique lines in text files.

- **`wc`**: 
	- Prints newline, word, and byte counts for files.  
  	- Used for counting lines, words, and characters in text.

#### Process management

- **`ps`**: 
	- Reports a snapshot of current processes.  
  	- Used for viewing running processes.

- **`top`**: 
	- Displays Linux tasks.  
  	- Used for monitoring system performance and processes.

- **`htop`**: 
	- Interactive process viewer.  
  	- Enhanced alternative to `top`.

- **`kill`**: 
	- Sends a signal to a process.  
  	- Used for terminating processes.

- **`pkill`**: 
	- Sends signals to processes by name.  
  	- Used for terminating processes by name.

- **`nice`**: 
	- Runs a command with modified scheduling priority.  
  	- Used for adjusting process priorities.

- **`renice`**: 
	- Alters priority of running processes.  
  	- Used for changing process priorities on the fly.

- **`nohup`**: 
	- Runs a command immune to hangups.  
  	- Used for running commands in the background.

#### System information

- **`uname`**: 
	- Prints system information.  
  	- Used for displaying system and kernel information.

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for checking disk space availability.

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for identifying disk usage by files and directories.

- **`free`**: 
	- Displays the amount of free and used memory in the system.  
  	- Used for monitoring memory usage.

- **`vmstat`**: 
	- Reports virtual memory statistics.  
  	- Used for monitoring system performance.

- **`uptime`**: 
	- Tells how long the system has been running.  
  	- Used for checking system uptime.

- **`dmesg`**: 
	- Prints kernel ring buffer messages.  
  	- Used for viewing system boot and diagnostic messages.

- **`lscpu`**: 
	- Displays information about the CPU architecture.  
  	- Used for checking CPU details.

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing storage device details.

- **`lsusb`**: 
	- Lists USB devices.  
  	- Used for checking connected USB devices.

- **`lspci`**: 
	- Lists PCI devices.  
  	- Used for viewing connected PCI devices.

- **`hostnamectl`**: 
	- Controls the system hostname.  
  	- Used for setting or querying the system's hostname.

- **`timedatectl`**: 
	- Controls the system time and date.  
  	- Used for setting or querying system time settings.

#### Software installation and management

- **`apt`**: 
	- High-level package management command for Debian-based distributions.  
  	- Used for managing software packages on Debian-based systems.

- **`yum`**: 
	- Package manager for RPM-based distributions.  
  	- Used for managing software packages on Red Hat-based systems.

- **`dnf`**: 
	- Next-generation package manager for RPM-based distributions.  
  	- Replacement for `yum`.

- **`rpm`**: 
	- RPM package manager.  
  	- Used for installing, querying, and managing RPM packages.

- **`snap`**: 
	- Package management system for installing snap packages.  
  	- Used for managing snap packages across Linux distributions.

- **`flatpak`**: 
	- System for building, distributing, and running sandboxed desktop applications.  
  	- Used for managing Flatpak packages.

#### Kernel module management

- **`lsmod`**: 
	- Shows the status of modules in the Linux Kernel.  
  	- Used for listing currently loaded kernel modules.

- **`modprobe`**: 
	- Adds and removes modules from the Linux kernel.  
  	- Used for managing kernel modules.

- **`insmod`**: 
	- Inserts a module into the Linux kernel.  
  	- Used for loading a single module.

- **`rmmod`**: 
	- Removes a module from the Linux kernel.  
  	- Used for unloading a single module.

- **`modinfo`**: 
	- Shows information about a Linux Kernel module.  
  	- Used for querying details of kernel modules.

- **`depmod`**: 
	- Generates modules.dep and map files.  
  	- Used for creating dependency files for kernel modules.

#### Boot process and system recovery

- **`grub`**: 
	- GRand Unified Bootloader, used for booting the system.  
  	- Used for managing boot configurations.

- **`grub2-mkconfig`**: 
	- Generates a GRUB2 configuration file.  
  	- Used for creating GRUB2 configuration.

- **`update-grub`**: 
	- Updates GRUB bootloader configuration.  
  	- Used for applying changes to GRUB.

- **`systemctl`**: 
	- Controls the systemd system and service manager.  
  	- Used for managing system services and targets.

- **`journalctl`**: 
	- Queries and displays messages from the journal.  
  	- Used for viewing system logs.

- **`rescue.target`**: 
	- Boots the system into rescue mode.  
  	- Used for system recovery.

- **`emergency.target`**: 
	- Boots the system into emergency mode.  
  	- Used for critical system recovery.

- **`initramfs`**: 
	- Initial RAM filesystem used during boot.  
  	- Used for pre-boot filesystem setup.

- **`dracut`**: 
	- Tool for creating initramfs images.  
  	- Used for generating initramfs.

#### Shell scripting

- **`bash`**: 
	- GNU Bourne Again SHell, command processor.  
  	- Used for writing and executing shell scripts.

- **`sh`**: 
	- Shell command interpreter.  
  	- Basic shell scripting environment.

- **`#!/bin/bash`**: 
	- Shebang line for bash scripts.  
  	- Used at the beginning of shell scripts to specify the interpreter.

- **`echo`**: 
	- Displays a line of text.  
  	- Commonly used for outputting text in scripts.

- **`read`**: 
	- Reads a line of input.  
  	- Used for getting user input in scripts.

- **`if`**: 
	- Conditional statement.  
  	- Used for decision making in scripts.

- **`else`**: 
	- Alternative conditional branch.  
  	- Used with `if` for branching logic.

- **`fi`**: 
	- Ends an `if` statement.  
  	- Used to close conditional blocks.

- **`for`**: 
	- Looping statement.  
  	- Used for iterating over items.

- **`while`**: 
	- Looping statement.  
  	- Used for repeating a block of commands while a condition is true.

- **`case`**: 
	- Multi-way branch statement.  
  	- Used for matching patterns.

- **`esac`**: 
	- Ends a `case` statement.  
  	- Used to close case blocks.

- **`function`**: 
	- Defines a function.  
  	- Used for creating reusable code blocks.

- **`$?`**: 
	- Returns the exit status of the last command.  
  	- Used for checking command success or failure.

- **`$0`**: 
	- Name of the script.  
  	- Used for referencing the script name.

- **`$1`, `$2`, ...**: 
	- Positional parameters.  
  	- Used for accessing script arguments.

- **`$#`**: 
	- Number of positional parameters.  
  	- Used for counting script arguments.

- **`$@`**: 
	- All positional parameters.  
  	- Used for accessing all arguments.

- **`shift`**: 
	- Shifts positional parameters.  
  	- Used for processing script arguments.

#### Create and restore system snapshots and backups

- **`rsync`**: 
	- Remote file and directory synchronization.  
  	- Used for copying and syncing files efficiently.

- **`tar`**: 
	- Archives files.  
  	- Used for creating and extracting backups.



- **`dd`**: 
	- Converts and copies files.  
  	- Used for low-level copying and disk imaging.

- **`cp`**: 
	- Copies files and directories.  
  	- Used for duplicating data for backups.

- **`scp`**: 
	- Secure copy (remote file copy program).  
  	- Used for securely copying files over a network.

- **`sftp`**: 
	- Secure File Transfer Protocol.  
  	- Used for transferring files securely.

- **`btrfs`**: 
	- B-tree Filesystem with snapshot capabilities.  
  	- Used for creating and managing filesystem snapshots.

- **`zfs`**: 
	- Zettabyte File System with advanced features like snapshots.  
  	- Used for managing filesystems and storage volumes.

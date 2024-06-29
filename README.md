# Linux-Cheatsheet

### Operations Deployment (25%)

#### Configure kernel parameters, persistent and non-persistent

- **`sysctl`**: 
	- Command to modify kernel parameters at runtime.  
  	- Commonly used in performance tuning and setting network-related parameters.
	```sh
	# View the current value of a kernel parameter
	sysctl net.ipv4.ip_forward
	
	# List all current kerneparameters and their values
	sysctl -a
	
	# Load ttings from a specified configuration file
	sysctl -p /path/to/your/sysctl.conf
	```

- **`/etc/sysctl.conf`**: 
	- Configuration file for kernel parameters that are read at boot.  
  	- Used for setting persistent kernel parameter changes.
	```sh
	# Enable IP forwarding (persistently)
	# Add the following line to /etc/sysctl.conf
	net.ipv4.ip_forward = 1
	
	# Set the maximum numr of open files (persistently)
	# Add the following line to /etc/sysctl.conf
	fs.file-max = 100000
	
	# Increase the sizof the receive buffer (persistently)
	# Add the following line to /etc/sysctl.conf
	net.core.rmem_max = 16777216
	```

- **`sysctl -w`**: 
	- Option to set kernel parameters dynamically.  
  	- Typically used for temporary changes that don't require a reboot.
	```sh
	# Enable IP forwarding (non-persistently)
	sysctl -w net.ipv4.ip_forward=1
	
	# Set the maximum number of on files (non-persistently)
	sysctl -w fs.file-max=100000
	
	# Increase the size of theeceive buffer (non-persistently)
	sysctl -w net.core.rmem_max=16777216
	<your-example>
	```
- **`/etc/sysctl.d/`**: 
	- Directory for additional kernel parameter configuration files.  
  	- Used for organizing kernel parameter settings in a modular way.
	```sh
	# Enable IP forwarding (persistently)
	# Create a file /etc/sysctl.d/99-ipforward.conf with the following content
	net.ipv4.ip_forward = 1
	
	# Set the maximum numr of open files (persistently)
	# Create a file /etc/sysctl.d/99-filemax.conf with the following content
	fs.file-max = 100000
	
	# Increase the sizof the receive buffer (persistently)
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
	
	# Dplay detailed information about processes
	ps aux
	
	# Dilay processes for a specific user
	ps -u username
	
	# List procees in a tree format
	ps -e --forest
	```

- **`top`**: 
	- Interactive tool for real-time system monitoring.  
  	- Commonly used to observe system load and process activity.
	```sh
	# Start top to monitor system processes in real-time
	top
	
	#tart top with batch mode operation for logging purposes
	top -b
	
	# Dilay top output sorted by memory usage
	top -o %MEM
	
	# Displayop output with only specific user processes
	top -u username
	```

- **`htop`**: 
	- Enhanced version of `top` with a more user-friendly interface.  
  	- Preferred by many for real-time process monitoring.
	```sh
	# Start htop to monitor system processes with an interactive UI
	htop
	
	# art htop sorted by CPU usage
	htop --sort-key PERCENT_CPU
	
	# Display only processes  a specific user
	htop -u username
	
	# Filter procees by command name
	htop -p $(pgrep -d ',' process_name)
	```

- **`systemctl`**: 
	- Command to manage systemd services.  
  	- Used for starting, stopping, enabling, and checking the status of services.
	```sh
	# Check the status of a service
	systemctl status apache2
	
	# Start a servi
	systemctl start apache2
	
	# Stop a servi
	systemctl stop apache2
	
	# Enable a service tstart on boot
	systemctl enable apache2
	
	# Reload systemd manag configuration
	systemctl daemon-reload
	```

- **`service`**: 
	- Legacy command to manage system services.  
  	- Often used on systems without systemd.
	```sh
	# Start a service
	service apache2 start
	
	# Stop a servi
	service apache2 stop
	
	# Restart a servi
	service apache2 restart
	
	# Check the status of service
	service apache2 status
	```

- **`journalctl`**: 
	- Command to query and display messages from the systemd journal.  
  	- Essential for troubleshooting system and service issues.
	```sh
	# View the entire system journal
	journalctl
	
	# View jrnal logs for a specific service
	journalctl -u apache2
	
	# View logs since t last boot
	journalctl -b
	
	# Follow nejournal entries in real-time
	journalctl -f
	```

- **`strace`**: 
	- Diagnostic tool to monitor system calls and signals.  
  	- Used for debugging and analyzing the behavior of applications.
	```sh
	# Trace system calls and signals of a command
	strace ls
	
	# Trace running process by PID
	strace -p 1234
	
	# Save stracoutput to a file
	strace -o output.txt ls
	
	# Trace only file-reled system calls
	strace -e trace=file ls
	```

- **`dmesg`**: 
	- Prints the message buffer of the kernel.  
  	- Useful for diagnosing hardware and boot issues.
	```sh
	# Print the kernel ring buffer messages
	dmesg
	
	# Vw dmesg output in a less pager
	dmesg | less
	
	# Filter dsg output for errors
	dmesg | grep -i error
	
	# Clear the kernel ng buffer
	dmesg -C
	```

- **`kill`**: 
	- Sends a signal to a process, usually to terminate it.  
  	- Used to stop processes manually.
	```sh
	# Kill a process by PID
	kill 1234
	
	# Send specific signal to a process
	kill -9 1234
	
	# Kill allrocesses with a specific name
	pkill -f process_name
	
	# List available sials
	kill -l
	```

- **`pkill`**: 
	- Sends a signal to processes based on name and other attributes.  
  	- Useful for terminating multiple processes matching certain criteria.
	```sh
	# Kill processes by name
	pkill apache2
	
	# Send a spific signal to processes by name
	pkill -9 apache2
	
	# Kill process owned by a specific user
	pkill -u username
	
	# Kill processematching a pattern
	pkill -f pattern
	```

- **`pgrep`**: 
	- Searches for processes based on name and other attributes.  
  	- Helps in finding process IDs matching specific patterns.
	```sh
	# List process IDs by name
	pgrep apache2
	
	# List procs IDs by name and user
	pgrep -u username apache2
	
	# List process IDs withull command matching
	pgrep -f pattern
	
	# List processDs with extended regular expression
	pgrep -e pattern
	```

- **`pidof`**: 
	- Finds the process ID of a running program.  
  	- Commonly used to locate process IDs by program name.
	```sh
	# Get the PID of a running program
	pidof apache2
	
	# Get the Ps of a running program with multiple instances
	pidof -x apache2
	
	# Get the PID  a running program with partial name match
	pidof -c partial_name
	```

- **`lsof`**: 
	- Lists open files and the processes that opened them.  
  	- Useful for troubleshooting file system and network issues.
	```sh
	# List all open files
	lsof
	
	# st open files by a specific process
	lsof -p 1234
	
	# List opefiles by a specific user
	lsof -u username
	
	# List open fis by a specific network port
	lsof -i :80
	```

- **`netstat`**: 
	- Displays network connections, routing tables, interface statistics.  
  	- Used for network troubleshooting and monitoring.
	```sh
	# Display network connections, routing tables, interface statistics
	netstat -a
	
	# Displanetwork connections with process information
	netstat -tpn
	
	# Display stening ports
	netstat -l
	
	# Displarouting table
	netstat -r
	```

- **`ss`**: 
	- Utility to investigate sockets and connections.  
  	- Often used as a modern alternative to `netstat`.
	```sh
	# Display all sockets
	ss -a
	
	# Dplay listening sockets
	ss -l
	
	# Dplay TCP connections
	ss -t
	
	# Dplay UDP connections
	ss -u
	
	# Dplay summary statistics
	ss -s
	```

#### Search for, install, validate, and maintain software packages or repositories

- **`yum`**:
  - Package manager for RPM-based distributions.
  - Used for installing, updating, and removing packages.
  ```sh
  # Install a package
  sudo yum install package-name

  # Update all packages
  sudo yum update

  # Remove a package
  sudo yum remove package-name

  # List installed packages
  yum list installed

  # Clean yum cache
  sudo yum clean all
  ```

- **`dnf`**:
  - Next-generation package manager for RPM-based distributions.
  - Replaces `yum` with enhanced features and performance.
  ```sh
  # Install a package
  sudo dnf install package-name

  # Update all packages
  sudo dnf update

  # Remove a package
  sudo dnf remove package-name

  # List installed packages
  dnf list installed

  # Clean dnf cache
  sudo dnf clean all
  ```

- **`apt`**:
  - Package manager for Debian-based distributions.
  - Commonly used for managing .deb packages.
  ```sh
  # Update package list
  sudo apt update

  # Upgrade installed packages
  sudo apt upgrade

  # Install a package
  sudo apt install package-name

  # Remove a package
  sudo apt remove package-name

  # Clean apt cache
  sudo apt clean
  ```

- **`rpm`**:
  - Package manager for RPM packages.
  - Used for installing, querying, verifying, updating, and removing RPM packages.
  ```sh
  # Install a package
  sudo rpm -i package-name.rpm

  # Update a package
  sudo rpm -U package-name.rpm

  # Remove a package
  sudo rpm -e package-name

  # Query installed packages
  rpm -qa

  # Verify a package
  rpm -V package-name
  ```

- **`dpkg`**:
  - Base package management system for Debian.
  - Used for low-level package operations.
  ```sh
  # Install a package
  sudo dpkg -i package-name.deb

  # Remove a package
  sudo dpkg -r package-name

  # List installed packages
  dpkg -l

  # Reconfigure an installed package
  sudo dpkg-reconfigure package-name

  # Verify package installation
  dpkg -V package-name
  ```

- **`snap`**:
  - Package manager for Snap packages.
  - Used for installing and managing containerized software packages.
  ```sh
  # Install a snap package
  sudo snap install package-name

  # Remove a snap package
  sudo snap remove package-name

  # List installed snap packages
  snap list

  # Refresh (update) snap packages
  sudo snap refresh

  # Find available snap packages
  snap find
  ```

- **`flatpak`**:
  - Package manager for Flatpak packages.
  - Used for installing and running sandboxed desktop applications.
  ```sh
  # Install a flatpak package
  sudo flatpak install repo-name package-name

  # Remove a flatpak package
  sudo flatpak uninstall package-name

  # List installed flatpak packages
  flatpak list

  # Update flatpak packages
  sudo flatpak update

  # Add a remote repository
  sudo flatpak remote-add --if-not-exists repo-name repo-url
  ```

- **`zypper`**:
  - Command line interface of ZYpp package manager for openSUSE.
  - Used for installing, updating, and managing software packages.
  ```sh
  # Install a package
  sudo zypper install package-name

  # Update all packages
  sudo zypper update

  # Remove a package
  sudo zypper remove package-name

  # List installed packages
  zypper search --installed-only

  # Clean zypper cache
  sudo zypper clean
  ```

- **`pip`**:
  - Package manager for Python packages.
  - Used to install and manage Python software libraries.
  ```sh
  # Install a package
  pip install package-name

  # Upgrade a package
  pip install --upgrade package-name

  # Remove a package
  pip uninstall package-name

  # List installed packages
  pip list

  # Show package information
  pip show package-name
  ```

- **`gem`**:
  - Package manager for Ruby packages.
  - Used to manage Ruby libraries (gems).
  ```sh
  # Install a gem
  gem install gem-name

  # Update a gem
  gem update gem-name

  # Remove a gem
  gem uninstall gem-name

  # List installed gems
  gem list

  # Show gem information
  gem info gem-name
  ```

- **`apt-key`**:
  - Manages keys for apt's trusted keyring.
  - Used to add and remove repository signing keys.
  ```sh
  # Add a new key
  sudo apt-key add key-file

  # List keys
  apt-key list

  # Remove a key
  sudo apt-key del key-id

  # Add a key from a URL
  wget -q -O - key-url | sudo apt-key add -

  # Export a key
  sudo apt-key export key-id > key-file
  ```

- **`yum-config-manager`**:
  - Manages yum repository configuration.
  - Used to add, enable, and disable repositories.
  ```sh
  # Add a new repository
  sudo yum-config-manager --add-repo repo-url

  # Enable a repository
  sudo yum-config-manager --enable repo-id

  # Disable a repository
  sudo yum-config-manager --disable repo-id

  # List all repositories
  yum-config-manager --list

  # Set repository options
  sudo yum-config-manager --setopt=option=value
  ```

- **`add-apt-repository`**:
  - Adds a repository to the sources list.
  - Used to include additional software sources.
  ```sh
  # Add a PPA repository
  sudo add-apt-repository ppa:repo-name

  # Remove a PPA repository
  sudo add-apt-repository --remove ppa:repo-name

  # Add a repository with a custom URI
  sudo add-apt-repository "deb [arch=amd64] http://repo-url/ $(lsb_release -cs) main"

  # Enable a disabled repository
  sudo add-apt-repository -y ppa:repo-name

  # Update package list after adding a repository
  sudo apt update
  ```

- **`update-rc.d`**:
  - Updates System-V style init script links.
  - Used to manage service runlevels in Debian-based systems.
  ```sh
  # Enable a service at boot
  sudo update-rc.d service-name defaults

  # Disable a service at boot
  sudo update-rc.d service-name disable

  # Remove a service
  sudo update-rc.d -f service-name remove

  # View service status
  update-rc.d -n service-name defaults

  # Reorder service start levels
  sudo update-rc.d service-name start 20 2 3 4 5 . stop 80 0 1 6 .
  ```

- **`systemctl enable/disable`**:
  - Enables or disables a service to start at boot.
  - Used to manage service startup in systemd systems.
  ```sh
  # Enable a service at boot
  sudo systemctl enable service-name

  # Disable a service at boot
  sudo systemctl disable service-name

  # Start a service
  sudo systemctl start service-name

  # Stop a service
  sudo systemctl stop service-name

  # Check service status
  systemctl status service-name
  ```

#### Recover from hardware, operating system, or filesystem failures

- **`fsck`** 
	- Filesystem consistency check and repair.
	- Used to check and repair filesystem errors.
```sh
# Check and repair the filesystem on /dev/sda1
fsck /dev/sda1

# Check the filesystem on /dev/sda1 without making changes
fsck -n /dev/sda1

# Automatically fix any detected errors on /dev/sda1
fsck -y /dev/sda1
```

- **`e2fsck`**
	- Filesystem consistency check for ext2/ext3/ext4 filesystems.
	- Commonly used for checking and fixing ext filesystems.
```sh
# Check and repair ext4 filesystem on /dev/sda2
e2fsck /dev/sda2

# Check the filesystem on /dev/sda2 without making changes
e2fsck -n /dev/sda2

# Automatically fix any detected errors on /dev/sda2
e2fsck -p /dev/sda2
```

- **`dd`**
	- Utility to convert and copy files at a low level.
	- Used for creating disk images and backups.
```sh
# Create a disk image of /dev/sda and save it as sda.img
dd if=/dev/sda of=/path/to/sda.img

# Write an image file to a USB drive
dd if=/path/to/image.iso of=/dev/sdb bs=4M

# Clone one disk to another
dd if=/dev/sda of=/dev/sdb
```

- **`smartctl`**
	- Controls and monitors storage devices using S.M.A.R.T.
	- Used for checking hard drive health.
```sh
# Display basic S.M.A.R.T. information for /dev/sda
smartctl -i /dev/sda

# Perform a short self-test on /dev/sda
smartctl -t short /dev/sda

# Display detailed S.M.A.R.T. health information for /dev/sda
smartctl -a /dev/sda
```

- **`mdadm`**
	- Manages MD (multiple device) software RAID arrays.
	- Used for creating, assembling, and monitoring RAID arrays.
```sh
# Create a RAID 1 array with two devices
mdadm --create --verbose /dev/md0 --level=1 --raid-devices=2 /dev/sda /dev/sdb

# Assemble a RAID array from existing devices
mdadm --assemble /dev/md0 /dev/sda /dev/sdb

# Monitor the status of a RAID array
mdadm --detail /dev/md0
```

- **`dracut`**
	- Tool for generating initramfs images.
	- Used for creating initial ramdisk environments.
```sh
# Generate an initramfs image for the current kernel
dracut --force

# Generate an initramfs image for a specific kernel version
dracut --kver 5.8.0-1-amd64 --force

# Include additional drivers in the initramfs image
dracut --add-drivers "driver1 driver2" --force
```

- **`initrd`**
	- Initial ramdisk used by the Linux kernel during boot.
	- Essential for loading necessary drivers before mounting the root filesystem.
```sh
# Create an initrd image with mkinitrd (specific to some distributions)
mkinitrd /boot/initrd.img-5.8.0-1-amd64 5.8.0-1-amd64

# List the contents of an initrd image
lsinitrd /boot/initrd.img-5.8.0-1-amd64

# Update the initrd image for the current kernel
update-initramfs -u
```

- **`grub`**
	- GRand Unified Bootloader, manages boot configurations.
	- Used for bootloader management and configuration.
```sh
# Update GRUB configuration after making changes
update-grub

# Install GRUB on the MBR of /dev/sda
grub-install /dev/sda

# Open GRUB configuration file for editing
nano /etc/default/grub
```

- **`rescue mode`**
	- Special boot mode for system recovery.
	- Used to troubleshoot and repair system boot issues.
```sh
# Boot into rescue mode from the GRUB menu
Select the "Advanced options" entry, then the "Rescue mode" entry

# From the boot prompt, enter rescue mode directly
systemctl rescue

# Using a live CD/USB, select the rescue mode option to boot into a recovery environment
Boot the live CD/USB and select "Rescue a broken system"
```

- **`systemctl rescue`**
	- Boots the system into rescue mode using systemd.
	- Used for minimal system repair tasks.
```sh
# Enter rescue mode immediately
systemctl rescue

# Reboot into rescue mode
systemctl reboot --force --force rescue.target

# Switch to rescue mode without rebooting
systemctl isolate rescue.target
```

#### Manage Virtual Machines (libvirt)

- **`virsh`**: 
	- Command-line interface for managing virtual machines via libvirt.
	- Used to create, control, and manage virtual machines.
	```sh
	# Connect to the default libvirt daemon
	virsh -c qemu:///system

	# List all defined virtual machines
	virsh list --all
	```

- **`virt-install`**: 
	- Tool to create new virtual machines.
	- Used to automate the installation of new VMs.
	```sh
	# Create a new VM with specified memory, disk, and network configuration
	virt-install --name=examplevm --memory=1024 --vcpus=1 --disk size=10 --cdrom=/path/to/os.iso --network network=default

	# Install a VM using a kickstart file for automated installation
	virt-install --name=examplevm --memory=2048 --vcpus=2 --disk size=20 --location=/path/to/os.iso --extra-args="ks=/path/to/kickstart.cfg"
	```

- **`virt-manager`**: 
	- Graphical tool for managing virtual machines.
	- Provides an interface for managing VMs.
	```sh
	# Launch virt-manager GUI
	virt-manager

	# Connect to a remote hypervisor
	virt-manager --connect qemu+ssh://username@remotehost/system
	```

- **`virt-clone`**: 
	- Clones existing virtual machines.
	- Used to duplicate VMs with unique configurations.
	```sh
	# Clone a VM named "sourcevm" to a new VM named "clonevm"
	virt-clone --original sourcevm --name clonevm --file /var/lib/libvirt/images/clonevm.img

	# Clone a VM and specify a new MAC address for the network interface
	virt-clone --original sourcevm --name clonevm --file /var/lib/libvirt/images/clonevm.img --mac 52:54:00:6b:29:56
	```

- **`virt-sysprep`**: 
	- Prepares a virtual machine for cloning.
	- Cleans and resets VM configurations.
	```sh
	# Run virt-sysprep on a VM disk image to reset machine-specific settings
	virt-sysprep -a /var/lib/libvirt/images/sourcevm.img

	# Exclude specific operations during sysprep
	virt-sysprep -a /var/lib/libvirt/images/sourcevm.img --operations -ssh-hostkeys,-udev-persistent-net
	```

- **`qemu-img`**: 
	- Creates, converts, and modifies disk images.
	- Used for handling virtual machine disk images.
	```sh
	# Create a new QCOW2 disk image
	qemu-img create -f qcow2 /var/lib/libvirt/images/newdisk.img 20G

	# Convert a VMDK image to QCOW2 format
	qemu-img convert -f vmdk -O qcow2 /path/to/source.vmdk /var/lib/libvirt/images/converted.img
	```

- **`libvirtd`**: 
	- Daemon for managing platform virtualization via libvirt.
	- Required for running and managing virtual machines.
	```sh
	# Start the libvirtd daemon
	systemctl start libvirtd

	# Enable libvirtd to start on boot
	systemctl enable libvirtd
	```

- **`virsh list`**: 
	- Lists all active virtual machines.
	- Used for monitoring running VMs.
	```sh
	# List all running VMs
	virsh list

	# List all VMs, including those that are not running
	virsh list --all
	```

- **`virsh start/stop`**: 
	- Starts or stops a specified virtual machine.
	- Used for controlling VM states.
	```sh
	# Start a VM named "examplevm"
	virsh start examplevm

	# Stop a running VM named "examplevm"
	virsh shutdown examplevm
	```

- **`virsh create/destroy`**: 
	- Creates or destroys a virtual machine instance.
	- Used for dynamic VM management.
	```sh
	# Create and start a VM from an XML file
	virsh create /path/to/vm.xml

	# Forcefully stop and destroy a running VM named "examplevm"
	virsh destroy examplevm
	```

#### Configure container engines, create and manage containers

- **`docker`**: 
	- Containerization platform for developing, shipping, and running applications.
	- Used for creating, managing, and running containers.
	```sh
	# Create and run a new container
	docker run -d -p 80:80 --name webserver nginx

	# List all running containers
	docker ps

	# Build a Docker image from a Dockerfile
	docker build -t myimage:latest .
	```

- **`podman`**: 
	- Daemonless container engine for managing OCI containers.
	- Used as a Docker alternative for container management.
	```sh
	# Create and run a new container
	podman run -d -p 80:80 --name webserver nginx

	# List all running containers
	podman ps

	# Build a container image from a Containerfile
	podman build -t myimage:latest .
	```

- **`buildah`**: 
	- Tool for building OCI images.
	- Used for creating and managing container images.
	```sh
	# Create a new image from a Dockerfile
	buildah bud -t myimage:latest .

	# Inspect an image
	buildah inspect myimage:latest

	# Push an image to a remote registry
	buildah push myimage:latest docker://registry.example.com/myimage:latest
	```

- **`crictl`**: 
	- CLI for CRI-compatible container runtimes.
	- Used for interacting with container runtimes in Kubernetes environments.
	```sh
	# List all containers
	crictl ps

	# Inspect a specific container
	crictl inspect <container_id>

	# Pull an image from a remote registry
	crictl pull nginx:latest
	```

- **`kubectl`**: 
	- CLI for Kubernetes cluster management.
	- Used for deploying, managing, and inspecting applications in Kubernetes.
	```sh
	# Apply a configuration to a Kubernetes cluster
	kubectl apply -f deployment.yaml

	# Get the status of all pods
	kubectl get pods

	# Describe a specific pod
	kubectl describe pod <pod_name>
	```

- **`docker-compose`**: 
	- Tool for defining and running multi-container Docker applications.
	- Used for orchestrating multi-container deployments.
	```sh
	# Start up defined services
	docker-compose up

	# Stop all running services
	docker-compose down

	# View the logs of all services
	docker-compose logs
	```

- **`docker build`**: 
	- Builds a Docker image from a Dockerfile.
	- Used for creating container images.
	```sh
	# Build an image from a Dockerfile
	docker build -t myimage:latest .

	# Build an image with a specific build context
	docker build -t myimage:latest /path/to/context

	# Build an image with no cache
	docker build --no-cache -t myimage:latest .
	```

- **`docker run`**: 
	- Runs a command in a new Docker container.
	- Used for starting containers from images.
	```sh
	# Run a container from an image
	docker run -d -p 80:80 --name webserver nginx

	# Run a container interactively
	docker run -it ubuntu bash

	# Run a container with environment variables
	docker run -d -e ENV_VAR=value --name app myapp:latest
	```

- **`docker ps`**: 
	- Lists running Docker containers.
	- Used for monitoring active containers.
	```sh
	# List all running containers
	docker ps

	# List all containers (running and stopped)
	docker ps -a

	# List running containers with format options
	docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	```

- **`docker images`**: 
	- Lists Docker images on the host.
	- Used for managing local container images.
	```sh
	# List all images
	docker images

	# List images with a specific format
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

	# List images with a filter
	docker images --filter "dangling=true"
	```

- **`docker network`**: 
	- Manages Docker networks.
	- Used for creating and managing container networks.
	```sh
	# List all Docker networks
	docker network ls

	# Create a new network
	docker network create mynetwork

	# Inspect a specific network
	docker network inspect mynetwork
	```

- **`docker volume`**: 
	- Manages Docker volumes.
	- Used for handling persistent storage for containers.
	```sh
	# List all Docker volumes
	docker volume ls

	# Create a new volume
	docker volume create myvolume

	# Inspect a specific volume
	docker volume inspect myvolume
	```

- **`docker inspect`**: 
	- Displays detailed information about Docker objects.
	- Used for troubleshooting and examining containers.
	```sh
	# Inspect a specific container
	docker inspect <container_id>

	# Inspect a specific image
	docker inspect <image_id>

	# Inspect a specific network
	docker inspect <network_id>
	```

- **`podman run`**: 
	- Runs a command in a new podman container.
	- Used similarly to `docker run` but without a daemon.
	```sh
	# Run a container from an image
	podman run -d -p 80:80 --name webserver nginx

	# Run a container interactively
	podman run -it ubuntu bash

	# Run a container with environment variables
	podman run -d -e ENV_VAR=value --name app myapp:latest
	```

- **`podman ps`**: 
	- Lists running podman containers.
	- Used for monitoring podman-managed containers.
	```sh
	# List all running containers
	podman ps

	# List all containers (running and stopped)
	podman ps -a

	# List running containers with format options
	podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	```

#### Create and enforce MAC using SELinux

- **`sestatus`**: 
	- Displays the current status of SELinux.  
  	- Used to check if SELinux is enabled and its current mode.
	<your-example>

- **`getsebool`**: 
	- Retrieves the current setting of an SELinux boolean.  
  	- Used to query boolean values for SELinux policies.
	<your-example>

- **`setsebool`**: 
	- Sets the current setting of an SELinux boolean.  
  	- Used to modify boolean values for policy tuning.
	<your-example>

- **`semanage`**: 
	- Manages SELinux policy components.  
  	- Used for configuring SELinux policy settings.
	<your-example>

- **`restorecon`**: 
	- Restores the default SELinux context for files.  
  	- Used to fix SELinux context issues on files.
	<your-example>

- **`chcon`**: 
	- Changes the SELinux security context of a file.  
  	- Used for setting custom SELinux contexts.
	<your-example>

- **`ls -Z`**: 
	- Lists files with their SELinux security context.  
  	- Used for viewing SELinux contexts of files.
	<your-example>

- **`ps -Z`**: 
	- Displays process security contexts.  
  	- Used to check SELinux contexts of running processes.
	<your-example>

- **`audit2allow`**: 
	- Generates SELinux policy allow rules from logs.  
  	- Used to create custom SELinux rules based on audit logs.
	<your-example>

- **`ausearch`**: 
	- Searches the audit logs based on specified criteria.  
  	- Used for querying SELinux audit logs.
	<your-example>

- **`/etc/selinux/config`**: 
	- Configuration file for SELinux settings.  
  	- Used for setting SELinux modes and policies.
	<your-example>

- **`semodule`**: 
	- Manages SELinux policy modules.  
  	- Used to install and manage SELinux policy modules.
	<your-example>

- **`setenforce`**: 
	- Switches SELinux between enforcing and permissive modes.  
  	- Used to temporarily change the enforcement mode of SELinux.

### Networking (25%)

#### Configure IPv4 and IPv6 networking and hostname resolution

- **`ip`**: 
	- Command for managing network interfaces and routes.  
  	- Used for configuring IP addresses, routes, and tunnels.
	```sh
	# Assign an IP address to an interface
	sudo ip addr add 192.168.1.10/24 dev eth0

	# Show the current IP addresses
	ip addr show

	# Add a default gateway
	sudo ip route add default via 192.168.1.1
	```

- **`ifconfig`**: 
	- Legacy tool for configuring network interfaces.  
  	- Often replaced by `ip` but still used in some scripts and systems.
	```sh
	# Display all network interfaces and their current status
	ifconfig

	# Assign an IP address to an interface
	sudo ifconfig eth0 192.168.1.10 netmask 255.255.255.0

	# Bring an interface up or down
	sudo ifconfig eth0 up
	sudo ifconfig eth0 down
	```

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for managing network connections and devices.
	```sh
	# Display all network connections
	nmcli con show

	# Connect to a Wi-Fi network
	nmcli dev wifi connect "SSID_NAME" password "PASSWORD"

	# Add a new static IP connection
	nmcli con add type ethernet ifname eth0 con-name static-eth0 ip4 192.168.1.10/24 gw4 192.168.1.1
	```

- **`nmtui`**: 
	- Text user interface for NetworkManager.  
  	- Provides a simpler interface for managing network settings.
	```sh
	# Launch the nmtui interface
	sudo nmtui

	# Edit a connection via nmtui
	# Use the interactive interface to select and edit connections

	# Activate a connection via nmtui
	# Use the interactive interface to activate connections
	```

- **`hostnamectl`**: 
	- Controls the system hostname.  
  	- Used for setting the system's hostname and related settings.
	```sh
	# Set the system hostname
	sudo hostnamectl set-hostname new-hostname

	# Check the current hostname
	hostnamectl

	# Set a transient hostname
	sudo hostnamectl set-hostname temporary-hostname --transient
	```

- **`systemctl restart network`**: 
	- Restarts the network service.  
  	- Used to apply network configuration changes.
	```sh
	# Restart the network service on a CentOS/RHEL system
	sudo systemctl restart network

	# Check the status of the network service
	sudo systemctl status network

	# Enable the network service to start on boot
	sudo systemctl enable network
	```

- **`/etc/hosts`**: 
	- Static table lookup for hostnames.  
  	- Used for local hostname resolution.
	```sh
	# Add a new hostname to the /etc/hosts file
	echo "192.168.1.10 myhostname" | sudo tee -a /etc/hosts

	# View the contents of the /etc/hosts file
	cat /etc/hosts

	# Remove an entry from the /etc/hosts file
	sudo sed -i '/192.168.1.10 myhostname/d' /etc/hosts
	```

- **`/etc/resolv.conf`**: 
	- Configuration file for DNS resolution.  
  	- Used for setting DNS servers and search domains.
	```sh
	# Add a new DNS server to /etc/resolv.conf
	echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

	# Set a search domain in /etc/resolv.conf
	echo "search example.com" | sudo tee -a /etc/resolv.conf

	# View the contents of /etc/resolv.conf
	cat /etc/resolv.conf
	```

- **`ping`**: 
	- Sends ICMP ECHO_REQUEST to network hosts.  
  	- Used for checking network connectivity.
	```sh
	# Ping a remote host to check connectivity
	ping google.com

	# Ping a remote host with a specified number of packets
	ping -c 4 google.com

	# Ping a remote host with IPv6
	ping6 google.com
	```

- **`traceroute`**: 
	- Traces the route packets take to a network host.  
  	- Used for diagnosing network path issues.
	```sh
	# Trace the route to a remote host
	traceroute google.com

	# Trace the route to a remote host using IPv6
	traceroute6 google.com

	# Trace the route to a remote host with a specified number of queries per hop
	traceroute -q 2 google.com
	```

- **`netplan`**: 
	- Network configuration tool for Ubuntu.  
  	- Used for configuring network settings via YAML files.
	```sh
	# Generate network configuration from netplan
	sudo netplan generate

	# Apply network configuration changes
	sudo netplan apply

	# Test netplan configuration
	sudo netplan try
	```

#### Set and synchronize system time using time servers

- **`timedatectl`**: 
	- Command to query and change the system clock and its settings.  
  	- Used for managing system time and synchronization.
	<your-example>

- **`ntpdate`**: 
	- Synchronizes the system clock with NTP servers.  
  	- Used for one-time clock synchronization.
	<your-example>

- **`chronyc`**: 
	- Command-line interface for the chrony NTP client.  
  	- Used for managing and monitoring chrony.
	<your-example>

- **`chronyd`**: 
	- Daemon for the chrony NTP client.  
  	- Used for maintaining accurate system time.
	<your-example>

- **`systemctl restart chronyd`**: 
	- Restarts the chrony daemon.  
  	- Used to apply chrony configuration changes.

#### Monitor and troubleshoot networking
	<your-example>

- **`netstat`**: 
	- Displays network connections, routing tables, and interface statistics.  
  	- Used for network troubleshooting and monitoring.
	<your-example>

- **`ss`**: 
	- Investigates sockets and network connections.  
  	- Modern alternative to `netstat`.
	<your-example>

- **`tcpdump`**: 
	- Network packet analyzer.  
  	- Used for capturing and analyzing network traffic.
	<your-example>

- **`wireshark`**: 
	- Network protocol analyzer with a graphical interface.  
  	- Used for in-depth network traffic analysis.
	<your-example>

- **`iftop`**: 
	- Displays bandwidth usage on an interface.  
  	- Used for monitoring network traffic in real-time.
	<your-example>

- **`nmap`**: 
	- Network scanner to discover hosts and services.  
  	- Used for network discovery and security auditing.
	<your-example>

- **`ping`**: 
	- Checks network connectivity by sending ICMP ECHO_REQUEST packets.  
  	- Commonly used to test if a host is reachable.
	<your-example>

- **`traceroute`**: 
	- Traces the path packets take to reach a host.  
  	- Used for diagnosing network path issues.
	<your-example>

- **`mtr`**: 
	- Combines the functionality of `ping` and `traceroute`.  
  	- Used for network diagnostic purposes.
	<your-example>

- **`dig`**: 
	- DNS lookup utility.  
  	- Used for querying DNS name servers.
	<your-example>

- **`nslookup`**: 
	- Queries DNS to obtain domain name or IP address mapping.  
  	- Used for DNS troubleshooting.
	<your-example>

- **`ethtool`**: 
	- Displays and modifies network interface parameters.  
  	- Used for managing Ethernet devices.
	<your-example>

- **`ip route`**: 
	- Shows/manages the IP routing table.  
  	- Used for configuring network routes.
	<your-example>

- **`ip link`**: 
	- Manages and displays network interfaces.  
  	- Used for configuring network interfaces.

#### Configure the OpenSSH server and client
	<your-example>

- **`sshd`**: 
	- Secure Shell daemon.  
  	- Provides secure encrypted communications between hosts.
	<your-example>

- **`sshd_config`**: 
	- Configuration file for the OpenSSH server.  
  	- Used to set SSH server options.
	<your-example>

- **`ssh`**: 
	- Secure Shell client.  
  	- Used to connect to SSH servers.
	<your-example>

- **`ssh-keygen`**: 
	- Generates, manages, and converts authentication keys for SSH.  
  	- Used for creating SSH key pairs.
	<your-example>

- **`scp`**: 
	- Secure copy program.  
  	- Used for copying files over SSH.
	<your-example>

- **`sftp`**: 
	- Secure file transfer program.  
  	- Used for transferring files over SSH.
	<your-example>

- **`systemctl restart sshd`**: 
	- Restarts the SSH daemon.  
  	- Used to apply SSH server configuration changes.

#### Configure packet filtering, port redirection, and NAT
	<your-example>

- **`iptables`**: 
	- Utility for configuring Linux kernel firewall implemented in netfilter.  
  	- Used for setting up, maintaining, and inspecting firewall rules.
	<your-example>

- **`firewalld`**: 
	- Dynamic firewall management tool with D-Bus interface.  
  	- Used for managing firewall rules in a more user-friendly way.
	<your-example>

- **`nftables`**: 
	- Replaces iptables as the Linux firewall utility.  
  	- Used for managing firewall rules with better performance and flexibility.
	<your-example>

- **`ufw`**: 
	- Uncomplicated Firewall, front-end for iptables.  
  	- Used for managing firewall rules easily.
	<your-example>

- **`ip6tables`**: 
	- IPv6 version of iptables.  
  	- Used for managing IPv6 firewall rules.
	<your-example>

- **`iptables-save`**: 
	- Saves the current iptables rules.  
  	- Used for exporting firewall rules to a file.
	<your-example>

- **`iptables-restore`**: 
	- Restores iptables rules from a file.  
  	- Used for importing firewall rules from a file.
	<your-example>

- **`firewall-cmd`**: 
	- Command-line interface for firewalld.  
  	- Used for managing firewalld configurations.

#### Configure static routing
	<your-example>

- **`ip route`**: 
	- Command to show/manages the IP routing table.  
  	- Used for configuring static routes.
	<your-example>

- **`route`**: 
	- Legacy command to show and manipulate the IP routing table.  
  	- Often replaced by `ip route`.
	<your-example>

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for configuring static routes via NetworkManager.
	<your-example>

- **`network-scripts`**: 
	- Scripts for network configuration in older Linux distributions.  
  	- Used for configuring network interfaces and routes.
	<your-example>

- **`/etc/sysconfig/network-scripts/route-<interface>`**: 
	- Configuration file for static routes in Red Hat-based systems.  
  	- Used for setting persistent static routes.

#### Configure bridge and bonding devices
	<your-example>

- **`brctl`**: 
	- Utility for configuring Ethernet bridge devices.  
  	- Used for creating and managing network bridges.
	<your-example>

- **`ip link`**: 
	- Command to manage and display network interfaces.  
  	- Used for configuring network bonding and bridging.
	<your-example>

- **`nmcli`**: 
	- Command-line interface for NetworkManager.  
  	- Used for configuring bonding and bridging via NetworkManager.
	<your-example>

- **`teamd`**: 
	- Daemon to manage team network devices.  
  	- Used for creating and managing

 network teams (bonding).
	<your-example>

- **`bonding`**: 
	- Linux kernel module for bonding multiple network interfaces.  
  	- Used for network interface bonding to increase throughput and redundancy.

#### Implement reverse proxies and load balancers
	<your-example>

- **`nginx`**: 
	- Web server and reverse proxy server.  
  	- Used for load balancing and reverse proxying HTTP and other protocols.
	<your-example>

- **`haproxy`**: 
	- High Availability Proxy, provides load balancing and high availability.  
  	- Used for distributing network traffic across multiple servers.
	<your-example>

- **`apache mod_proxy`**: 
	- Apache module for proxy/gateway functionality.  
  	- Used for reverse proxying with the Apache web server.
	<your-example>

- **`varnish`**: 
	- HTTP accelerator and reverse proxy.  
  	- Used for caching and load balancing HTTP traffic.
	<your-example>

- **`squid`**: 
	- Caching and forwarding HTTP proxy.  
  	- Used for caching web traffic and implementing reverse proxies.

### Storage (20%)

#### Configure and manage LVM storage

- **`lvcreate`**: 
	- Creates a logical volume.  
  	- Used for creating new LVM logical volumes.
	<your-example>

- **`vgcreate`**: 
	- Creates a volume group.  
  	- Used for creating new LVM volume groups.
	<your-example>

- **`pvcreate`**: 
	- Prepares a physical volume for use by LVM.  
  	- Used for initializing physical storage devices.
	<your-example>

- **`lvextend`**: 
	- Extends the size of a logical volume.  
  	- Used for increasing storage capacity of an LVM logical volume.
	<your-example>

- **`vgreduce`**: 
	- Removes physical volumes from a volume group.  
  	- Used for reducing the size of a volume group.
	<your-example>

- **`pvmove`**: 
	- Moves physical extents from one physical volume to another.  
  	- Used for balancing storage or replacing disks.
	<your-example>

- **`vgextend`**: 
	- Adds physical volumes to a volume group.  
  	- Used for expanding the storage pool of a volume group.
	<your-example>

- **`lvremove`**: 
	- Removes a logical volume.  
  	- Used for deleting LVM logical volumes.
	<your-example>

- **`lvresize`**: 
	- Resizes a logical volume.  
  	- Used for adjusting the size of an LVM logical volume.
	<your-example>

- **`vgremove`**: 
	- Removes a volume group.  
  	- Used for deleting LVM volume groups.
	<your-example>

- **`pvremove`**: 
	- Removes a physical volume.  
  	- Used for decommissioning physical storage devices from LVM.
	<your-example>

- **`lvdisplay`**: 
	- Displays information about logical volumes.  
  	- Used for viewing LVM logical volume details.
	<your-example>

- **`vgdisplay`**: 
	- Displays information about volume groups.  
  	- Used for viewing LVM volume group details.
	<your-example>

- **`pvdisplay`**: 
	- Displays information about physical volumes.  
  	- Used for viewing LVM physical volume details.

#### Manage and configure the virtual file system
	<your-example>

- **`mount`**: 
	- Attaches a filesystem to the directory tree.  
  	- Used for mounting filesystems.
	<your-example>

- **`umount`**: 
	- Detaches a filesystem from the directory tree.  
  	- Used for unmounting filesystems.
	<your-example>

- **`fstab`**: 
	- Configuration file for static filesystem mounts.  
  	- Used for setting persistent mount points.
	<your-example>

- **`/etc/fstab`**: 
	- Contains information about filesystems and their mount points.  
  	- Used for automating the mounting of filesystems at boot.
	<your-example>

- **`/etc/mtab`**: 
	- Lists currently mounted filesystems.  
  	- Used for tracking active mounts.
	<your-example>

- **`findmnt`**: 
	- Displays target mount point information.  
  	- Used for finding and displaying filesystem mount points.
	<your-example>

- **`blkid`**: 
	- Displays or modifies block device attributes.  
  	- Used for querying block device information.
	<your-example>

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for monitoring disk space usage.
	<your-example>

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for checking disk usage of files and directories.
	<your-example>

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing block device details.
	<your-example>

- **`resize2fs`**: 
	- Resizes ext2/3/4 filesystems.  
  	- Used for expanding or shrinking ext filesystems.
	<your-example>

- **`xfs_growfs`**: 
	- Expands an XFS filesystem.  
  	- Used for increasing the size of an XFS filesystem.

#### Create, manage, and troubleshoot filesystems
	<your-example>

- **`mkfs`**: 
	- Builds a Linux filesystem on a device.  
  	- Used for creating new filesystems.
	<your-example>

- **`mkfs.ext4`**: 
	- Creates an ext4 filesystem.  
  	- Commonly used for creating ext4 filesystems.
	<your-example>

- **`mkfs.xfs`**: 
	- Creates an XFS filesystem.  
  	- Used for creating XFS filesystems.
	<your-example>

- **`tune2fs`**: 
	- Adjusts tunable filesystem parameters on ext filesystems.  
  	- Used for modifying ext filesystem settings.
	<your-example>

- **`fsck`**: 
	- Checks and repairs a Linux filesystem.  
  	- Used for filesystem integrity checks and repairs.
	<your-example>

- **`e2fsck`**: 
	- Checks and repairs ext2/3/4 filesystems.  
  	- Used for ext filesystem maintenance.
	<your-example>

- **`xfs_repair`**: 
	- Repairs an XFS filesystem.  
  	- Used for fixing issues in XFS filesystems.
	<your-example>

- **`mount -o loop`**: 
	- Mounts a file as a filesystem.  
  	- Used for mounting disk image files.

#### Use remote filesystems and network block devices
	<your-example>

- **`nfs`**: 
	- Network File System, allows remote file sharing.  
  	- Used for accessing files over a network.
	<your-example>

- **`nfs-client`**: 
	- Mounts NFS shares on a client system.  
  	- Used for connecting to NFS shares.
	<your-example>

- **`nfs-server`**: 
	- Exports directories over NFS.  
  	- Used for sharing directories over a network.
	<your-example>

- **`mount.nfs`**: 
	- Mounts NFS filesystems.  
  	- Used for attaching NFS shares.
	<your-example>

- **`/etc/exports`**: 
	- Configuration file for NFS exports.  
  	- Used for defining shared directories in NFS.
	<your-example>

- **`autofs`**: 
	- Automounts filesystems on demand.  
  	- Used for automatically mounting remote filesystems.
	<your-example>

- **`iscsiadm`**: 
	- Manages iSCSI initiator connections.  
  	- Used for connecting to iSCSI targets.
	<your-example>

- **`targetcli`**: 
	- Configures iSCSI targets.  
  	- Used for managing iSCSI target configurations.
	<your-example>

- **`mount.cifs`**: 
	- Mounts CIFS filesystems (Samba shares).  
  	- Used for accessing Windows shares.
	<your-example>

- **`/etc/fstab`**: 
	- Used for automating the mounting of remote filesystems.  
  	- Contains entries for remote filesystem mounts.

#### Configure and manage swap space
	<your-example>

- **`swapon`**: 
	- Enables devices and files for paging and swapping.  
  	- Used for activating swap space.
	<your-example>

- **`swapoff`**: 
	- Disables devices and files for paging and swapping.  
  	- Used for deactivating swap space.
	<your-example>

- **`mkswap`**: 
	- Sets up a Linux swap area.  
  	- Used for initializing swap space on a device.
	<your-example>

- **`/etc/fstab`**: 
	- Contains entries for swap space.  
  	- Used for defining swap space to be activated at boot.
	<your-example>

- **`free`**: 
	- Displays the amount of free and used memory in the system.  
  	- Used for monitoring memory and swap usage.
	<your-example>

- **`vmstat`**: 
	- Reports virtual memory statistics.  
  	- Used for monitoring system performance and swap activity.

#### Configure filesystem automounters
	<your-example>

- **`autofs`**: 
	- Service that automatically mounts filesystems.  
  	- Used for on-demand mounting of filesystems.
	<your-example>

- **`/etc/auto.master`**: 
	- Master map for autofs.  
  	- Used for configuring automount points.
	<your-example>

- **`/etc/auto.misc`**: 
	- Example automounter map file.  
  	- Used for defining specific automount configurations.
	<your-example>

- **`automount`**: 
	- Command to reload the automounter.  
  	- Used for applying changes to autofs configurations.

#### Monitor storage performance
	<your-example>

- **`iostat`**: 
	- Reports CPU and I/O statistics for devices and partitions.  
  	- Used for monitoring storage performance.
	<your-example>

- **`iotop`**: 
	- Displays I/O usage by processes.  
  	- Used for identifying processes with high I/O activity.
	<your-example>

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for checking available storage space.
	<your-example>

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for identifying disk usage by files and directories.
	<your-example>

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing storage device details.
	<your-example>

- **`smartctl`**: 
	- Controls and monitors storage devices using S.M.A.R.T.  
  	- Used for checking the health of storage devices.
	<your-example>

- **`blkid`**: 
	- Displays or modifies block device attributes.  
  	- Used for querying and setting block device metadata.

### Essential Commands (20%)

#### Basic Git Operations

- **`git clone`**: 
	- Clones a repository into a new directory.  
  	- Used for copying remote repositories locally.
	<your-example>

- **`git commit`**: 
	- Records changes to the repository.  
  	- Used for saving snapshots of the project history.
	<your-example>

- **`git pull`**: 
	- Fetches from and integrates with another repository.  
  	- Used for updating local repositories with remote changes.
	<your-example>

- **`git push`**: 
	- Updates remote refs along with associated objects.  
  	- Used for sharing local changes with remote repositories.
	<your-example>

- **`git branch`**: 
	- Lists, creates, or deletes branches.  
  	- Used for managing project branches.
	<your-example>

- **`git checkout`**: 
	- Switches branches or restores working tree files.  
  	- Used for changing branches or reverting changes.
	<your-example>

- **

`git merge`**: 
	- Joins two or more development histories together.  
  	- Used for combining changes from different branches.
	<your-example>

- **`git status`**: 
	- Shows the working tree status.  
  	- Used for viewing the current state of the repository.
	<your-example>

- **`git log`**: 
	- Shows the commit logs.  
  	- Used for reviewing project history.
	<your-example>

- **`git diff`**: 
	- Shows changes between commits, commit and working tree, etc.  
  	- Used for comparing changes.

#### File management, archiving, and compression
	<your-example>

- **`ls`**: 
	- Lists directory contents.  
  	- Used for viewing files and directories.
	<your-example>

- **`cp`**: 
	- Copies files and directories.  
  	- Used for duplicating files and directories.
	<your-example>

- **`mv`**: 
	- Moves or renames files and directories.  
  	- Used for relocating or renaming files and directories.
	<your-example>

- **`rm`**: 
	- Removes files or directories.  
  	- Used for deleting files and directories.
	<your-example>

- **`tar`**: 
	- Archives files.  
  	- Used for creating and extracting tar archives.
	<your-example>

- **`gzip`**: 
	- Compresses or decompresses files.  
  	- Used for handling gzip compressed files.
	<your-example>

- **`bzip2`**: 
	- Compresses or decompresses files.  
  	- Used for handling bzip2 compressed files.
	<your-example>

- **`zip`**: 
	- Packages and compresses files.  
  	- Used for creating zip archives.
	<your-example>

- **`unzip`**: 
	- Extracts files from a zip archive.  
  	- Used for unpacking zip files.

#### Text processing
	<your-example>

- **`grep`**: 
	- Searches for patterns in files.  
  	- Used for finding specific text within files.
	<your-example>

- **`awk`**: 
	- Pattern scanning and processing language.  
  	- Used for text processing and data extraction.
	<your-example>

- **`sed`**: 
	- Stream editor for filtering and transforming text.  
  	- Used for text manipulation and editing.
	<your-example>

- **`cut`**: 
	- Removes sections from each line of files.  
  	- Used for extracting parts of text files.
	<your-example>

- **`sort`**: 
	- Sorts lines of text files.  
  	- Used for ordering text data.
	<your-example>

- **`uniq`**: 
	- Reports or omits repeated lines.  
  	- Used for finding unique lines in text files.
	<your-example>

- **`wc`**: 
	- Prints newline, word, and byte counts for files.  
  	- Used for counting lines, words, and characters in text.

#### Process management
	<your-example>

- **`ps`**: 
	- Reports a snapshot of current processes.  
  	- Used for viewing running processes.
	<your-example>

- **`top`**: 
	- Displays Linux tasks.  
  	- Used for monitoring system performance and processes.
	<your-example>

- **`htop`**: 
	- Interactive process viewer.  
  	- Enhanced alternative to `top`.
	<your-example>

- **`kill`**: 
	- Sends a signal to a process.  
  	- Used for terminating processes.
	<your-example>

- **`pkill`**: 
	- Sends signals to processes by name.  
  	- Used for terminating processes by name.
	<your-example>

- **`nice`**: 
	- Runs a command with modified scheduling priority.  
  	- Used for adjusting process priorities.
	<your-example>

- **`renice`**: 
	- Alters priority of running processes.  
  	- Used for changing process priorities on the fly.
	<your-example>

- **`nohup`**: 
	- Runs a command immune to hangups.  
  	- Used for running commands in the background.

#### System information
	<your-example>

- **`uname`**: 
	- Prints system information.  
  	- Used for displaying system and kernel information.
	<your-example>

- **`df`**: 
	- Reports filesystem disk space usage.  
  	- Used for checking disk space availability.
	<your-example>

- **`du`**: 
	- Estimates file and directory space usage.  
  	- Used for identifying disk usage by files and directories.
	<your-example>

- **`free`**: 
	- Displays the amount of free and used memory in the system.  
  	- Used for monitoring memory usage.
	<your-example>

- **`vmstat`**: 
	- Reports virtual memory statistics.  
  	- Used for monitoring system performance.
	<your-example>

- **`uptime`**: 
	- Tells how long the system has been running.  
  	- Used for checking system uptime.
	<your-example>

- **`dmesg`**: 
	- Prints kernel ring buffer messages.  
  	- Used for viewing system boot and diagnostic messages.
	<your-example>

- **`lscpu`**: 
	- Displays information about the CPU architecture.  
  	- Used for checking CPU details.
	<your-example>

- **`lsblk`**: 
	- Lists information about block devices.  
  	- Used for viewing storage device details.
	<your-example>

- **`lsusb`**: 
	- Lists USB devices.  
  	- Used for checking connected USB devices.
	<your-example>

- **`lspci`**: 
	- Lists PCI devices.  
  	- Used for viewing connected PCI devices.
	<your-example>

- **`hostnamectl`**: 
	- Controls the system hostname.  
  	- Used for setting or querying the system's hostname.
	<your-example>

- **`timedatectl`**: 
	- Controls the system time and date.  
  	- Used for setting or querying system time settings.

#### Software installation and management
	<your-example>

- **`apt`**: 
	- High-level package management command for Debian-based distributions.  
  	- Used for managing software packages on Debian-based systems.
	<your-example>

- **`yum`**: 
	- Package manager for RPM-based distributions.  
  	- Used for managing software packages on Red Hat-based systems.
	<your-example>

- **`dnf`**: 
	- Next-generation package manager for RPM-based distributions.  
  	- Replacement for `yum`.
	<your-example>

- **`rpm`**: 
	- RPM package manager.  
  	- Used for installing, querying, and managing RPM packages.
	<your-example>

- **`snap`**: 
	- Package management system for installing snap packages.  
  	- Used for managing snap packages across Linux distributions.
	<your-example>

- **`flatpak`**: 
	- System for building, distributing, and running sandboxed desktop applications.  
  	- Used for managing Flatpak packages.

#### Kernel module management
	<your-example>

- **`lsmod`**: 
	- Shows the status of modules in the Linux Kernel.  
  	- Used for listing currently loaded kernel modules.
	<your-example>

- **`modprobe`**: 
	- Adds and removes modules from the Linux kernel.  
  	- Used for managing kernel modules.
	<your-example>

- **`insmod`**: 
	- Inserts a module into the Linux kernel.  
  	- Used for loading a single module.
	<your-example>

- **`rmmod`**: 
	- Removes a module from the Linux kernel.  
  	- Used for unloading a single module.
	<your-example>

- **`modinfo`**: 
	- Shows information about a Linux Kernel module.  
  	- Used for querying details of kernel modules.
	<your-example>

- **`depmod`**: 
	- Generates modules.dep and map files.  
  	- Used for creating dependency files for kernel modules.

#### Boot process and system recovery
	<your-example>

- **`grub`**: 
	- GRand Unified Bootloader, used for booting the system.  
  	- Used for managing boot configurations.
	<your-example>

- **`grub2-mkconfig`**: 
	- Generates a GRUB2 configuration file.  
  	- Used for creating GRUB2 configuration.
	<your-example>

- **`update-grub`**: 
	- Updates GRUB bootloader configuration.  
  	- Used for applying changes to GRUB.
	<your-example>

- **`systemctl`**: 
	- Controls the systemd system and service manager.  
  	- Used for managing system services and targets.
	<your-example>

- **`journalctl`**: 
	- Queries and displays messages from the journal.  
  	- Used for viewing system logs.
	<your-example>

- **`rescue.target`**: 
	- Boots the system into rescue mode.  
  	- Used for system recovery.
	<your-example>

- **`emergency.target`**: 
	- Boots the system into emergency mode.  
  	- Used for critical system recovery.
	<your-example>

- **`initramfs`**: 
	- Initial RAM filesystem used during boot.  
  	- Used for pre-boot filesystem setup.
	<your-example>

- **`dracut`**: 
	- Tool for creating initramfs images.  
  	- Used for generating initramfs.

#### Shell scripting
	<your-example>

- **`bash`**: 
	- GNU Bourne Again SHell, command processor.  
  	- Used for writing and executing shell scripts.
	<your-example>

- **`sh`**: 
	- Shell command interpreter.  
  	- Basic shell scripting environment.
	<your-example>

- **`#!/bin/bash`**: 
	- Shebang line for bash scripts.  
  	- Used at the beginning of shell scripts to specify the interpreter.
	<your-example>

- **`echo`**: 
	- Displays a line of text.  
  	- Commonly used for outputting text in scripts.
	<your-example>

- **`read`**: 
	- Reads a line of input.  
  	- Used for getting user input in scripts.
	<your-example>

- **`if`**: 
	- Conditional statement.  
  	- Used for decision making in scripts.
	<your-example>

- **`else`**: 
	- Alternative conditional branch.  
  	- Used with `if` for branching logic.
	<your-example>

- **`fi`**: 
	- Ends an `if` statement.  
  	- Used to close conditional blocks.
	<your-example>

- **`for`**: 
	- Looping statement.  
  	- Used for iterating over items.
	<your-example>

- **`while`**: 
	- Looping statement.  
  	- Used for repeating a block of commands while a condition is true.
	<your-example>

- **`case`**: 
	- Multi-way branch statement.  
  	- Used for matching patterns.
	<your-example>

- **`esac`**: 
	- Ends a `case` statement.  
  	- Used to close case blocks.
	<your-example>

- **`function`**: 
	- Defines a function.  
  	- Used for creating reusable code blocks.
	<your-example>

- **`$?`**: 
	- Returns the exit status of the last command.  
  	- Used for checking command success or failure.
	<your-example>

- **`$0`**: 
	- Name of the script.  
  	- Used for referencing the script name.
	<your-example>

- **`$1`, `$2`, ...**: 
	- Positional parameters.  
  	- Used for accessing script arguments.
	<your-example>

- **`$#`**: 
	- Number of positional parameters.  
  	- Used for counting script arguments.
	<your-example>

- **`$@`**: 
	- All positional parameters.  
  	- Used for accessing all arguments.
	<your-example>

- **`shift`**: 
	- Shifts positional parameters.  
  	- Used for processing script arguments.

#### Create and restore system snapshots and backups
	<your-example>

- **`rsync`**: 
	- Remote file and directory synchronization.  
  	- Used for copying and syncing files efficiently.
	<your-example>

- **`tar`**: 
	- Archives files.  
  	- Used for creating and extracting backups.


	<your-example>

- **`dd`**: 
	- Converts and copies files.  
  	- Used for low-level copying and disk imaging.
	<your-example>

- **`cp`**: 
	- Copies files and directories.  
  	- Used for duplicating data for backups.
	<your-example>

- **`scp`**: 
	- Secure copy (remote file copy program).  
  	- Used for securely copying files over a network.
	<your-example>

- **`sftp`**: 
	- Secure File Transfer Protocol.  
  	- Used for transferring files securely.
	<your-example>

- **`btrfs`**: 
	- B-tree Filesystem with snapshot capabilities.  
  	- Used for creating and managing filesystem snapshots.
	<your-example>

- **`zfs`**: 
	- Zettabyte File System with advanced features like snapshots.  
  	- Used for managing filesystems and storage volumes.

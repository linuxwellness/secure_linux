#!/bin/bash

# Create the security logs directory
sudo mkdir /var/log/security

# Install ClamAV
sudo apt install clamav -y

# Update virus definitions
sudo freshclam

# Configure regular scans
echo "0 6 * * 0 clamscan -r / --exclude-dir=/sys/ --exclude-dir=/proc/ --exclude-dir=/dev/ --exclude-dir=/var/lib/clamav && sudo cp /var/log/clamav/clamscan.log /var/log/security" | sudo crontab -

# Schedule automatic updates for virus definitions
sudo sed -i 's/^#0 \* \* \* \* \(.*\)$/0 * * * * \1/' /etc/cron.d/clamav-freshclam

# Enable the ClamAV daemon
sudo systemctl enable clamav-freshclam

# Start the ClamAV daemon
sudo systemctl start clamav-freshclam

# Enable on-access scanning (optional)
sudo sed -i 's/^#OnAccessPrevention \(.*\)$/OnAccessPrevention \1/' /etc/clamav/clamd.conf

# Restart the ClamAV daemon
sudo systemctl restart clamav-daemon

# Verify ClamAV installation
clamscan --version

# Install rkhunter
sudo apt-get install rkhunter -y

# Update rkhunter database
sudo rkhunter --update

# Configure rkhunter to run scheduled scans
sudo sed -i 's/^CRON_DAILY_RUN=".*"$/CRON_DAILY_RUN="true"/' /etc/default/rkhunter

# Install chkrootkit
sudo apt-get install chkrootkit -y

# Configure chkrootkit to run scheduled scans
sudo mv /etc/cron.daily/chkrootkit /etc/cron.weekly/

# Schedule regular updates of rkhunter database and scans
echo "0 2 * * * root /usr/bin/rkhunter --update --quiet && sudo cp /var/log/rkhunter.log /var/log/security" | sudo tee /etc/cron.d/rkhunter
echo "30 2 * * * root /usr/bin/rkhunter --cronjob --report-warnings-only --quiet" | sudo tee --append /etc/cron.d/rkhunter

# Schedule daily execution of chkrootkit and copy its log
echo "0 3 * * * root /usr/sbin/chkrootkit && sudo cp /var/log/chkrootkit.log /var/log/security" | sudo tee /etc/cron.d/chkrootkit

# Install YARA and AppArmor
sudo apt-get install yara apparmor -y

# Create a folder to store the YARA rules
rules_folder="/etc/yara_rules"
sudo mkdir -p "$rules_folder"

# Download the YARA rules from the GitHub repository
git clone https://github.com/linuxwellness/secure_linux.git "$rules_folder"

# Generate AppArmor profiles for all programs
sudo aa-genprof /bin/*
sudo aa-genprof /sbin/*
sudo aa-genprof /usr/bin/*
sudo aa-genprof /usr/sbin/*

# Enable the generated AppArmor profiles and set to complain mode
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.*
sudo apparmor_parser -r /etc/apparmor.d/sbin.*
sudo apparmor_parser -r /etc/apparmor.d/bin.*
sudo aa-complain /etc/apparmor.d/usr.bin.*
sudo aa-complain /etc/apparmor.d/sbin.*
sudo aa-complain /etc/apparmor.d/bin.*

# Echo the run_yara function directly into the script file
echo '
# Function to run YARA
run_yara() {
    # Run YARA to scan for malware
    yara -r "$rules_folder" \
        /bin /sbin \
        /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
        /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 \
        /home /var /tmp /etc
 # Check if YARA detected any matches
    if [[ -n $yara_output ]]; then
      # Create a log file with current date and time
        log_file="/var/log/security/yar_$(date +"%Y%m%d_%H%M%S").log"

        # Write the YARA matches and output to the log file
        echo "YARA detected matches:" >> "$log_file"
        echo "$yara_output" >> "$log_file"
        
  # Loop through the YARA output to get affected programs
        affected_programs=()
        while IFS= read -r line; do
            # Extract the affected program path from the YARA output line
            affected_program=$(echo "$line" | cut -d':' -f1)
            affected_programs+=("$affected_program")
        done <<< "$yara_output"
  
  # Switch AppArmor profiles to deny and kill mode for affected programs
        for program in "${affected_programs[@]}"; do
            profile="/etc/apparmor.d/${program#/*}"
            sudo aa-enforce "$profile"
            sudo aa-logprof "$profile"
        done
    fi
}

# Run the YARA function
run_yara' | sudo tee "/etc/yara-malware-scanner.sh" > /dev/null

# Set the script file as executable
sudo chmod +x "/etc/yara-malware-scanner.sh"

# Create the YARA Malware Scanner service file
service_file="/etc/systemd/system/yara-malware-scanner.service"

# Generate the service file content
service_content="[Unit]
Description=YARA Malware Scanner
After=network.target

[Service]
ExecStart=/etc/yara-malware-scanner.sh

[Install]
WantedBy=multi-user.target"

# Create the service file
echo "$service_content" | sudo tee "$service_file" > /dev/null

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable yara-malware-scanner.service
sudo systemctl start yara-malware-scanner.service

# Install UFW if it's not already installed
sudo apt-get install ufw -y

# Reset UFW to default settings
sudo ufw --force reset

# Set default incoming policy to deny
sudo ufw default deny incoming

# Allow outgoing connections
sudo ufw default allow outgoing

# Allow incoming HTTPS (443) connections
sudo ufw allow 443

# Enable UFW firewall
sudo ufw --force enable

# Define the log directory to monitor
log_directory="/var/log/security"

# Define the keywords to look for
keywords=("malware" "attack" "intrusion" "exploit" "vulnerability")

# Create the log monitor script file
script_file="/etc/log_monitor.sh"
echo "#!/bin/bash" > "$script_file"
echo "log_directory=\"$log_directory\"" >> "$script_file"
echo "keywords=(" >> "$script_file"
for keyword in "${keywords[@]}"; do
  echo "  \"$keyword\"" >> "$script_file"
done
echo ")" >> "$script_file"
echo "send_alert() { echo \"ALERT: Security issue detected. Please check the logs in \$log_directory\"; }" >> "$script_file"
echo "monitor_logs() { tail -f \"\$log_directory\"/* | while IFS= read -r line; do for keyword in \"\${keywords[@]}\"; do if [[ \$line =~ \$keyword ]]; then send_alert; break; fi; done; done; }" >> "$script_file"
echo "monitor_logs &" >> "$script_file"

# Make the script executable
chmod +x "$script_file"

# Create the systemd service unit file
service_file="/etc/systemd/system/log-monitor.service"
echo "[Unit]" > "$service_file"
echo "Description=Log Monitor" >> "$service_file"
echo "After=network.target" >> "$service_file"
echo "" >> "$service_file"
echo "[Service]" >> "$service_file"
echo "ExecStart=$script_file" >> "$service_file"
echo "" >> "$service_file"
echo "[Install]" >> "$service_file"
echo "WantedBy=multi-user.target" >> "$service_file"

# Reload systemd and enable the service
systemctl daemon-reload
systemctl enable log-monitor.service
systemctl start log-monitor.service

#Create a service that sets the kernel parameters at startup
sudo nano /etc/systemd/system/kernel-settings.service

# Define the service file path
service_file="/etc/systemd/system/kernel-parameters.service"

# Create the systemd service file
echo "[Unit]
Description=Set Kernel Parameters
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/set_kernel_parameters.sh

[Install]
WantedBy=multi-user.target" | sudo tee -a "$service_file" > /dev/null

# Make the script file executable
chmod +x /etc/set_kernel_parameters.sh

# Save the script file with the desired kernel parameters
{
  echo '# Set the kernel parameters'
  echo 'sysctl -w kernel.kptr_restrict=2'
  echo 'sysctl -w kernel.dmesg_restrict=1'
  echo 'sysctl -w kernel.printk="3 3 3 3"'
  echo 'sysctl -w kernel.unprivileged_bpf_disabled=1'
  echo 'sysctl -w net.core.bpf_jit_harden=2'
  echo 'sysctl -w dev.tty.ldisc_autoload=0'
  echo 'sysctl -w vm.unprivileged_userfaultfd=0'
  echo 'sysctl -w kernel.kexec_load_disabled=1'
  echo 'sysctl -w kernel.sysrq=4'
  echo 'sysctl -w kernel.unprivileged_userns_clone=0'
  echo 'sysctl -w kernel.perf_event_paranoid=3'
  echo 'sysctl -w net.ipv4.tcp_syncookies=1'
  echo 'sysctl -w net.ipv4.tcp_rfc1337=1'
  echo 'sysctl -w net.ipv4.conf.all.rp_filter=1'
  echo 'sysctl -w net.ipv4.conf.default.rp_filter=1'
  echo 'sysctl -w net.ipv4.conf.all.accept_redirects=0'
  echo 'sysctl -w net.ipv4.conf.default.accept_redirects=0'
  echo 'sysctl -w net.ipv4.conf.all.secure_redirects=0'
  echo 'sysctl -w net.ipv4.conf.default.secure_redirects=0'
  echo 'sysctl -w net.ipv6.conf.all.accept_redirects=0'
  echo 'sysctl -w net.ipv6.conf.default.accept_redirects=0'
  echo 'sysctl -w net.ipv4.conf.all.send_redirects=0'
  echo 'sysctl -w net.ipv4.conf.default.send_redirects=0'
  echo 'sysctl -w net.ipv4.icmp_echo_ignore_all=1'
  echo 'sysctl -w net.ipv4.conf.all.accept_source_route=0'
  echo 'sysctl -w net.ipv4.conf.default.accept_source_route=0'
  echo 'sysctl -w net.ipv6.conf.all.accept_source_route=0'
  echo 'sysctl -w net.ipv6.conf.default.accept_source_route=0'
  echo 'sysctl -w net.ipv6.conf.all.accept_ra=0'
  echo 'sysctl -w net.ipv6.conf.default.accept_ra=0'
  echo 'sysctl -w net.ipv4.tcp_sack=0'
  echo 'sysctl -w net.ipv4.tcp_dsack=0'
  echo 'sysctl -w net.ipv4.tcp_fack=0'
  echo 'sysctl -w kernel.yama.ptrace_scope=2'
  echo 'sysctl -w vm.mmap_rnd_bits=32'
  echo 'sysctl -w vm.mmap_rnd_compat_bits=16'
  echo 'sysctl -w kernel.deny_new_usb=1'
  echo 'sysctl -w fs.protected_symlinks=1'
  echo 'sysctl -w fs.protected_hardlinks=1'
  echo 'sysctl -w fs.protected_fifos=2'
  echo 'sysctl -w fs.protected_regular=2'
  echo 'sysctl -w slab_nomerge=1'
  echo 'sysctl -w init_on_alloc=1'
  echo 'sysctl -w init_on_free=1'
  echo 'sysctl -w page_alloc.shuffle=1'
  echo 'sysctl -w pti=on'
  echo 'sysctl -w randomize_kstack_offset=on'
  echo 'sysctl -w vsyscall=none'
  echo 'sysctl -w debugfs=off'
  echo 'sysctl -w kernel.core_pattern="|/bin/false"'
  echo 'sysctl -w fs.suid_dumpable=0'
  echo 'sysctl -w vm.swappiness=1'
  echo 'sysctl -w net.ipv6.conf.all.use_tempaddr=2'
  echo 'sysctl -w net.ipv6.conf.default.use_tempaddr=2'
  echo 'sysctl -w random.trust_cpu=off'
  echo 'sysctl -w intel_iommu=on'
  echo 'sysctl -w amd_iommu=on'
  echo 'sysctl -w modules.sig_enforce=1'
} | sudo tee /etc/set_kernel_parameters.sh > /dev/null

# Set the ownership and permissions for the script file
sudo chown root:root /etc/set_kernel_parameters.sh
sudo chmod 755 /etc/set_kernel_parameters.sh

# Reload the systemd daemon and enable the service
sudo systemctl daemon-reload
sudo systemctl enable kernel-parameters.service
sudo systemctl start kernel-parameters.service


# Kernel module blacklisting
echo 'install firewire-core /bin/false' | sudo tee /etc/modprobe.d/firewire-blacklist.conf > /dev/null
echo 'install thunderbolt /bin/false' | sudo tee /etc/modprobe.d/thunderbolt-blacklist.conf > /dev/null

# Early kernel module loading
echo 'jitterentropy_rng' | sudo tee /usr/lib/modules-load.d/jitterentropy.conf > /dev/null

# systemd-networkd configuration
cat <<EOF | sudo tee /etc/systemd/network/ipv6-privacy.conf > /dev/null
[Network]
IPv6PrivacyExtensions=kernel
EOF

# NetworkManager configuration
cat <<EOF | sudo tee /etc/NetworkManager/NetworkManager.conf > /dev/null
[connection]
ipv6.ip6-privacy=2
EOF

# coredump configuration
echo '[Coredump]' | sudo tee /etc/systemd/coredump.conf.d/disable.conf > /dev/null
echo 'Storage=none' | sudo tee -a /etc/systemd/coredump.conf.d/disable.conf > /dev/null

# Security limits configuration
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf > /dev/null

# Xwrapper.config configuration
echo 'needs_root_rights = no' | sudo tee /etc/X11/Xwrapper.config > /dev/null

# Secure /etc/fstab configuration
cat <<EOF | sudo tee -a /etc/fstab > /dev/null
/        /          ext4    defaults                              1 1
/home    /home      ext4    defaults,nosuid,noexec,nodev          1 2
/tmp     /tmp       ext4    defaults,bind,nosuid,noexec,nodev     1 2
/var     /var       ext4    defaults,bind,nosuid                  1 2
/boot    /boot      ext4    defaults,nosuid,noexec,nodev          1 2
EOF

# Mount /proc configuration
sudo sed -i '/^proc / s/defaults/defaults,hidepid=2,gid=proc/' /etc/fstab

# APT configuration
echo 'APT::Sandbox::Seccomp "true";' | sudo tee /etc/apt/apt.conf.d/40sandbox > /dev/null

# systemd-boot configuration
echo 'editor no' | sudo tee /boot/loader/loader.conf > /dev/null

# GRUB configuration
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="<quiet>"/' /etc/default/grub
sudo update-grub

# Rounds option in passwd PAM configuration
sudo sed -i '/^password .* pam_unix.so/ s/$/ rounds=65536/' /etc/pam.d/passwd

# PAM configuration
cat <<EOF | sudo tee -a /etc/pam.d/passwd > /dev/null
password required pam_pwquality.so retry=2 minlen=15 difok=6 dcredit=-3 ucredit=-2 lcredit=-2 ocredit=-3 enforce_for_root
password required pam_unix.so use_authtok sha512 shadow
EOF
echo 'auth optional pam_faildelay.so delay=4000000' | sudo tee -a /etc/pam.d/system-login > /dev/null

# Remove user from group
sudo gpasswd -d $user adm

# systemd service configuration
echo -e '[Service]\nSupplementaryGroups=sysfs' | sudo tee /etc/systemd/system/user@.service.d/sysfs.conf > /dev/null

# systemd service sandboxing
echo -e '[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectHostname=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
PrivateTmp=true
PrivateUsers=true
PrivateDevices=true
PrivateIPC=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET
RestrictNamespaces=true
SystemCallFilter=write read openat close brk fstat lseek mmap mprotect munmap rt_sigaction rt_sigprocmask ioctl nanosleep select access execve getuid arch_prctl set_tid_address set_robust_list prlimit64 pread64 getrandom
SystemCallArchitectures=native
UMask=0077
IPAddressDeny=any
AppArmorProfile=/etc/apparmor.d/*' | sudo tee /etc/systemd/system/user@.service.d/sandbox.conf > /dev/null


# Set directory permissions
sudo chmod 700 /home/$user
sudo chmod 700 /boot /usr/src /lib/modules /usr/lib/modules

# Preload hardened memory allocator
echo '/usr/lib/libhardened_malloc.so' | sudo tee /etc/ld.so.preload > /dev/null

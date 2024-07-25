#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Install required packages
apt update
apt install -y ufw aide

##V-238228
apt-get install libpam-pwquality -y 

# Path to the configuration file
config_file="/etc/security/pwquality.conf"
#Check if the line already exists and modify it, or add it if it doesn't exist
if grep -q "^enforcing\s*=" "$config_file"; then
  # If the line exists, replace it
  sed -i 's/^enforcing\s*=.*/enforcing = 1/' "$config_file"
  echo "Updated existing 'enforcing' line in $config_file"
else
  # If the line doesn't exist, add it
  echo "enforcing = 1" >> "$config_file"
  echo "Added 'enforcing = 1' to $config_file"
fi

# Path to the configuration file
config_file="/etc/pam.d/common-password"

# The line we want to add or modify
new_line="password requisite pam_pwquality.so retry=3"

# Check if the file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  #exit 1
fi

# Check if a line starting with "password requisite pam_pwquality.so" exists
if grep -q "^password[[:space:]]*requisite[[:space:]]*pam_pwquality.so" "$config_file"; then
  # If it exists, replace the entire line
  sed -i 's/^password[[:space:]]*requisite[[:space:]]*pam_pwquality.so.*$/'"$new_line"'/' "$config_file"
  echo "Updated existing pam_pwquality.so line in $config_file"
else
  # If it doesn't exist, add the new line
  echo "$new_line" >> "$config_file"
  echo "Added new pam_pwquality.so line to $config_file"
fi

##V-238231
apt-get install -y opensc-pkcs11

##V-238298
apt-get install -y auditd 
systemctl enable auditd.service
augenrules --load

##V-238200 
apt-get  install vlock

##V-238230
apt install -y libpam-pkcs11

##V-238371
apt install -y aide

# Configure AIDE (Advanced Intrusion Detection Environment)
rm /var/lib/aide/aide.db.new
sudo aideinit
cp -pf /var/lib/aide/aide.db.new /var/lib/aide/aide.db -y

##V-238354
apt-get install ufw

# Enable and configure firewall
ufw enable
ufw default deny incoming
ufw default allow outgoing

##V-238201

# Paths
config_dir="/etc/pam_pkcs11"
config_file="$config_dir/pam_pkcs11.conf"
example_file="/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example"

# Ensure the directory exists
if [ ! -d "$config_dir" ]; then
  echo "Creating directory $config_dir"
  mkdir -p "$config_dir"
fi

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  if [ -f "$example_file" ]; then
    echo "Copying example configuration file to $config_file"
    # Copy the file, overwriting the destination if it exists
    cp -f "$source_file" "$destination_file"
  else
    echo "Error: Example configuration file $example_file not found."
    exit 1
  fi
fi

# Modify the configuration file
if grep -q "use_mappers=" "$config_file"; then
  # If the line exists, modify it
  sed -i 's/\(use_mappers=.*\)null/\1pwent,null/' "$config_file"
  echo "Updated existing 'use_mappers' line in $config_file"
else
  # If the line doesn't exist, add it
  echo "use_mappers=pwent,null" >> "$config_file"
  echo "Added 'use_mappers=pwent,null' to $config_file"
fi

##V-238218
# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
 # exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the required lines
add_or_update_config "PermitEmptyPasswords" "no"
add_or_update_config "PermitUserEnvironment" "no"

# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
sudo systemctl restart sshd.service

##V-238219

# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to uncomment or add a configuration line
uncomment_or_add_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#\s*$key" "$config_file"; then
    # If the line exists but is commented out, uncomment it and set the value
    sed -i "s/^#\s*$key.*/$key $value/" "$config_file"
    echo "Uncommented and set '$key' to '$value' in $config_file"
  elif grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}


##V-238209


# Path to the login.defs configuration file
config_file="/etc/login.defs"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the UMASK parameter
add_or_update_config "UMASK" "077"

##V-238210
# Paths to configuration files
pam_config_file="/etc/pam.d/common-auth"
ssh_config_file="/etc/ssh/sshd_config"

# Ensure the PAM configuration file exists
if [ ! -f "$pam_config_file" ]; then
  echo "Error: $pam_config_file does not exist."
  exit 1
fi

# Ensure the SSH configuration file exists
if [ ! -f "$ssh_config_file" ]; then
  echo "Error: $ssh_config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line in a file
add_or_update_config() {
  local file="$1"
  local key="$2"
  local value="$3"
  if grep -q "^$key" "$file"; then
    # If the line exists, replace it
    sed -i "s|^$key.*|$key $value|" "$file"
    echo "Updated '$key' to '$value' in $file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$file"
    echo "Added '$key $value' to $file"
  fi
}

# Add or update the PAM configuration line
pam_line="auth [success=2 default=ignore] pam_pkcs11.so"
if grep -q "^auth.*pam_pkcs11.so" "$pam_config_file"; then
  # If the line exists, replace it
  sed -i "s|^auth.*pam_pkcs11.so.*|$pam_line|" "$pam_config_file"
  echo "Updated existing 'pam_pkcs11.so' line in $pam_config_file"
else
  # If the line doesn't exist, add it
  echo "$pam_line" >> "$pam_config_file"
  echo "Added 'pam_pkcs11.so' line to $pam_config_file"
fi

# Add or update the SSH configuration line
add_or_update_config "$ssh_config_file" "PubkeyAuthentication" "yes"

# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
sudo systemctl restart sshd.service

##V-238211

# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the UsePAM line
add_or_update_config "UsePAM" "yes"


# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
systemctl restart sshd.service


##V-238212
# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the ClientAliveCountMax line
add_or_update_config "ClientAliveCountMax" "1"

# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
systemctl restart sshd.service

##V-238213
# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the ClientAliveInterval line
add_or_update_config "ClientAliveInterval" "600"


# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
systemctl restart sshd.service

##V-238216

# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the MACs line
add_or_update_config "MACs" "hmac-sha2-512,hmac-sha2-256"

# Reload the SSH daemon to apply changes
echo "Reloading SSH daemon..."
systemctl reload sshd.service

##V-238217
# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the Ciphers line
add_or_update_config "Ciphers" "aes256-ctr,aes192-ctr,aes128-ctr"


# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
systemctl restart sshd.service

##V-238220
# Path to the SSH configuration file
config_file="/etc/ssh/sshd_config"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^#*\s*$key" "$config_file"; then
    # If the line exists (commented or uncommented), replace it
    sed -i "s/^#*\s*$key.*/$key $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$config_file"
    echo "Added '$key $value' to $config_file"
  fi
}

# Add or update the X11UseLocalhost line
add_or_update_config "X11UseLocalhost" "yes"

# Restart the SSH daemon to apply changes
echo "Restarting SSH daemon..."
systemctl restart sshd.service



##V-238225
# Path to the pwquality configuration file
config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist. Creating a new one."
  touch "$config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$config_file"
    echo "Added '$key=$value' to $config_file"
  fi
}

# Add or update the minlen parameter
add_or_update_config "minlen" "15"

##V-238227

# Path to the pwquality configuration file
config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist. Creating a new one."
  touch "$config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$config_file"
    echo "Added '$key=$value' to $config_file"
  fi
}

# Add or update the dictcheck parameter
add_or_update_config "dictcheck" "1"

##V-238228
# Install the pam_pwquality package
echo "Installing libpam-pwquality package..."
apt-get install libpam-pwquality -y

# Path to the pwquality configuration file
pwquality_config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$pwquality_config_file" ]; then
  echo "Creating $pwquality_config_file as it does not exist."
  touch "$pwquality_config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local file="$1"
  local key="$2"
  local value="$3"
  if grep -q "^$key" "$file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$file"
    echo "Updated '$key' to '$value' in $file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$file"
    echo "Added '$key=$value' to $file"
  fi
}

# Add or update the enforcing parameter
add_or_update_config "$pwquality_config_file" "enforcing" "1"

# Path to the common-password configuration file
common_password_file="/etc/pam.d/common-password"

# Ensure the common-password configuration file exists
if [ ! -f "$common_password_file" ]; then
  echo "Error: $common_password_file does not exist."
  #exit 1
fi

# Add or update the pam_pwquality.so line
pam_pwquality_line="password requisite pam_pwquality.so retry=3"
if grep -q "^password.*pam_pwquality.so" "$common_password_file"; then
  # If the line exists, replace it
  sed -i "s|^password.*pam_pwquality.so.*|$pam_pwquality_line|" "$common_password_file"
  echo "Updated existing pam_pwquality.so line in $common_password_file"
else
  # If the line doesn't exist, add it
  echo "$pam_pwquality_line" >> "$common_password_file"
  echo "Added pam_pwquality.so line to $common_password_file"
fi

##V-238229
# Paths
config_dir="/etc/pam_pkcs11"
config_file="$config_dir/pam_pkcs11.conf"
example_file="/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz"

# Ensure the pam_pkcs11 directory exists
if [ ! -d "$config_dir" ]; then
  echo "Creating directory $config_dir"
  mkdir -p "$config_dir"
fi

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  if [ -f "$example_file" ]; then
    echo "Copying example configuration file to $config_file"
    gunzip -c "$example_file" > "$config_file"
  else
    echo "Error: Example configuration file $example_file not found."
    exit 1
  fi
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key = $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key = $value" >> "$config_file"
    echo "Added '$key = $value' to $config_file"
  fi
}

# Check the use_pkcs11_module setting
pkcs11_module=$(grep "^use_pkcs11_module" "$config_file" | awk '{print $2}')
if [ -z "$pkcs11_module" ]; then
  echo "Error: 'use_pkcs11_module' not found in $config_file."
  exit 1
else
  echo "Using PKCS#11 module: $pkcs11_module"
fi

# Add or update the cert_policy line
add_or_update_config "cert_policy" "ca,signature,ocsp_on"

##v-238233
# Paths
config_dir="/etc/pam_pkcs11"
config_file="$config_dir/pam_pkcs11.conf"
example_file="/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz"

# Ensure the pam_pkcs11 directory exists
if [ ! -d "$config_dir" ]; then
  echo "Creating directory $config_dir"
  mkdir -p "$config_dir"
fi

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  if [ -f "$example_file" ]; then
    echo "Copying example configuration file to $config_file"
    gunzip -c "$example_file" > "$config_file"
  else
    echo "Error: Example configuration file $example_file not found."
    exit 1
  fi
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key = $value/" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key = $value" >> "$config_file"
    echo "Added '$key = $value' to $config_file"
  fi
}

# Add or update the cert_policy line
add_or_update_config "cert_policy" "ca,signature,ocsp_on,crl_auto"


##V-238238
# Path to the audit rules file
audit_rules_file="/etc/audit/rules.d/stig.rules"

# Ensure the audit rules file exists
if [ ! -f "$audit_rules_file" ]; then
  echo "Error: $audit_rules_file does not exist."
  exit 1
fi

# Function to add or update an audit rule
add_or_update_audit_rule() {
  local rule="$1"
  if grep -q "^$rule" "$audit_rules_file"; then
    # If the rule exists, replace it
    sed -i "s|^$rule.*|$rule|" "$audit_rules_file"
    echo "Updated audit rule: $rule"
  else
    # If the rule doesn't exist, add it
    echo "$rule" >> "$audit_rules_file"
    echo "Added audit rule: $rule"
  fi
}

# Define the audit rule for /etc/passwd
audit_rule="-w /etc/passwd -p wa -k usergroup_modification"

# Add or update the audit rule
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /etc/group -p wa -k usergroup_modification "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /etc/shadow -p wa -k usergroup_modification "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /etc/gshadow -p wa -k usergroup_modification"
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /etc/security/opasswd -p wa -k usergroup_modification "
add_or_update_audit_rule "$audit_rule"

audit_rule=" -a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-umount "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh "
add_or_update_audit_rule "$audit_rule"

audit_rule="--a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/log/tallylog -p wa -k logins "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/log/faillog -p wa -k logins "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/log/lastlog -p wa -k logins "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab"
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete "
add_or_update_audit_rule "$audit_rule"

audit_rule="-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/log/wtmp -p wa -k logins "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/run/utmp -p wa -k logins"
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /var/log/btmp -p wa -k logins"
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /sbin/modprobe -p x -k modules "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /bin/kmod -p x -k modules "
add_or_update_audit_rule "$audit_rule"

audit_rule="-w /usr/sbin/fdisk -p x -k fdisk "
add_or_update_audit_rule "$audit_rule"

audit_rule=""
add_or_update_audit_rule "$audit_rule"

audit_rule=""
add_or_update_audit_rule "$audit_rule"

audit_rule=""
add_or_update_audit_rule "$audit_rule"

audit_rule=""
add_or_update_audit_rule "$audit_rule"

audit_rule=""
add_or_update_audit_rule "$audit_rule"



# Reload the audit rules
echo "Reloading audit rules..."
sudo augenrules --load

##V-238244
# Path to the auditd configuration file
auditd_config_file="/etc/audit/auditd.conf"

# Ensure the auditd configuration file exists
if [ ! -f "$auditd_config_file" ]; then
  echo "Error: $auditd_config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$auditd_config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key = $value/" "$auditd_config_file"
    echo "Updated '$key' to '$value' in $auditd_config_file"
  else
    # If the line doesn't exist, add it
    echo "$key = $value" >> "$auditd_config_file"
    echo "Added '$key = $value' to $auditd_config_file"
  fi
}

# Add or update the disk_full_action line
add_or_update_config "disk_full_action" "HALT"

# Restart the auditd service to apply changes
echo "Restarting auditd service..."
sudo systemctl restart auditd.service

##V-238249
chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

##V-238250
chown root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

##V-238251
chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

##V-238300
# List of common audit tools
audit_tools=(
    "/sbin/auditd"
    "/sbin/audispd"
    "/sbin/aureport"
    "/sbin/ausearch"
    "/sbin/auditctl"
    "/sbin/autrace"
    "/sbin/augenrules"
)

# Function to check and set permissions
check_and_set_permissions() {
    local tool="$1"
    if [ -f "$tool" ]; then
        current_perms=$(stat -c "%a" "$tool")
        if [ "$current_perms" -ne 755 ]; then
            echo "Setting permissions for $tool to 0755"
            sudo chmod 0755 "$tool"
        else
            echo "Permissions for $tool are already set to 0755"
        fi
    else
        echo "Warning: $tool does not exist."
    fi
}

##V-238301
# Function to check and set ownership
check_and_set_ownership() {
    local tool="$1"
    if [ -f "$tool" ]; then
        current_owner=$(stat -c "%U" "$tool")
        if [ "$current_owner" != "root" ]; then
            echo "Changing owner of $tool to root"
            sudo chown root "$tool"
        else
            echo "Owner of $tool is already root"
        fi
    else
        echo "Warning: $tool does not exist."
    fi
}

# Check ownership for each audit tool
for tool in "${audit_tools[@]}"; do
    check_and_set_ownership "$tool"
done

##V-238302
# Function to check and set group ownership
check_and_set_group_ownership() {
    local tool="$1"
    if [ -f "$tool" ]; then
        current_group=$(stat -c "%G" "$tool")
        if [ "$current_group" != "root" ]; then
            echo "Changing group of $tool to root"
            sudo chown :root "$tool"
        else
            echo "Group of $tool is already root"
        fi
    else
        echo "Warning: $tool does not exist."
    fi
}

# Check group ownership for each audit tool
for tool in "${audit_tools[@]}"; do
    check_and_set_group_ownership "$tool"
done

##V=238330
useradd -D -f 35 

##V-238333
# Set TCP syncookies temporarily
echo "Setting TCP syncookies to 1 temporarily..."
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Check the current value of tcp_syncookies
current_value=$(sysctl -n net.ipv4.tcp_syncookies)
echo "Current value of net.ipv4.tcp_syncookies: $current_value"

# Ensure the value is set to 1 permanently
if [ "$current_value" -ne 1 ]; then
  echo "Updating /etc/sysctl.conf to set net.ipv4.tcp_syncookies = 1"
  echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
else
  echo "The value is already set to 1 in /etc/sysctl.conf."
fi

# Reload sysctl settings
echo "Reloading sysctl settings..."
sudo sysctl -p

##V-238337
sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;

##V-238370
# Path to the unattended upgrades configuration file
config_file="/etc/apt/apt.conf.d/50unattended-upgrades"

# Ensure the configuration file exists
if [ ! -f "$config_file" ]; then
  echo "Error: $config_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$config_file"; then
    # If the line exists, replace it
    sed -i "s|^$key.*|$key \"$value\";|" "$config_file"
    echo "Updated '$key' to '$value' in $config_file"
  else
    # If the line doesn't exist, add it
    echo "$key \"$value\";" >> "$config_file"
    echo "Added '$key' to $config_file"
  fi
}

# Add or update the Remove-Unused-Dependencies line
add_or_update_config "Unattended-Upgrade::Remove-Unused-Dependencies" "true"

# Add or update the Remove-Unused-Kernel-Packages line
add_or_update_config "Unattended-Upgrade::Remove-Unused-Kernel-Packages" "true"

echo "APT configuration for unattended upgrades has been updated successfully."

##V-251505
sudo su -c "echo install usb-storage /bin/false >> /etc/modprobe.d/DISASTIG.conf"
sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"


##V-238202
# Path to the login.defs configuration file
login_defs_file="/etc/login.defs"

# Ensure the login.defs file exists
if [ ! -f "$login_defs_file" ]; then
  echo "Error: $login_defs_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$login_defs_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key $value/" "$login_defs_file"
    echo "Updated '$key' to '$value' in $login_defs_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$login_defs_file"
    echo "Added '$key' to $login_defs_file"
  fi
}

# Add or update the PASS_MIN_DAYS line
add_or_update_config "PASS_MIN_DAYS" "1"

echo "Minimum password lifetime has been set to 1 day in $login_defs_file."
 
 ##V-238203

# Path to the login.defs configuration file
login_defs_file="/etc/login.defs"

# Ensure the login.defs file exists
if [ ! -f "$login_defs_file" ]; then
  echo "Error: $login_defs_file does not exist."
  exit 1
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$login_defs_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key $value/" "$login_defs_file"
    echo "Updated '$key' to '$value' in $login_defs_file"
  else
    # If the line doesn't exist, add it
    echo "$key $value" >> "$login_defs_file"
    echo "Added '$key' to $login_defs_file"
  fi
}

# Add or update the PASS_MAX_DAYS line
add_or_update_config "PASS_MAX_DAYS" "60"

echo "Maximum password lifetime has been set to 60 days in $login_defs_file."

##V-238221
# Path to the pwquality configuration file
pwquality_config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$pwquality_config_file" ]; then
  echo "Creating $pwquality_config_file as it does not exist."
  touch "$pwquality_config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$pwquality_config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$pwquality_config_file"
    echo "Updated '$key' to '$value' in $pwquality_config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$pwquality_config_file"
    echo "Added '$key=$value' to $pwquality_config_file"
  fi
}

# Add or update the ucredit line
add_or_update_config "ucredit" "-1"

echo "The 'ucredit' parameter has been set to -1 in $pwquality_config_file."


##V-238222
# Path to the pwquality configuration file
pwquality_config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$pwquality_config_file" ]; then
  echo "Creating $pwquality_config_file as it does not exist."
  touch "$pwquality_config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$pwquality_config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$pwquality_config_file"
    echo "Updated '$key' to '$value' in $pwquality_config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$pwquality_config_file"
    echo "Added '$key=$value' to $pwquality_config_file"
  fi
}

# Add or update the lcredit line
add_or_update_config "lcredit" "-1"

echo "The 'lcredit' parameter has been set to -1 in $pwquality_config_file."

##V-238223
# Path to the pwquality configuration file
pwquality_config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$pwquality_config_file" ]; then
  echo "Creating $pwquality_config_file as it does not exist."
  touch "$pwquality_config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$pwquality_config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$pwquality_config_file"
    echo "Updated '$key' to '$value' in $pwquality_config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$pwquality_config_file"
    echo "Added '$key=$value' to $pwquality_config_file"
  fi
}

# Add or update the dcredit line
add_or_update_config "dcredit" "-1"

echo "The 'dcredit' parameter has been set to -1 in $pwquality_config_file."

##V-238224

# Path to the pwquality configuration file
pwquality_config_file="/etc/security/pwquality.conf"

# Ensure the configuration file exists
if [ ! -f "$pwquality_config_file" ]; then
  echo "Creating $pwquality_config_file as it does not exist."
  touch "$pwquality_config_file"
fi

# Function to add or update a configuration line
add_or_update_config() {
  local key="$1"
  local value="$2"
  if grep -q "^$key" "$pwquality_config_file"; then
    # If the line exists, replace it
    sed -i "s/^$key.*/$key=$value/" "$pwquality_config_file"
    echo "Updated '$key' to '$value' in $pwquality_config_file"
  else
    # If the line doesn't exist, add it
    echo "$key=$value" >> "$pwquality_config_file"
    echo "Added '$key=$value' to $pwquality_config_file"
  fi
}

# Add or update the difok line
add_or_update_config "difok" "8"

add_or_update_config "ocredit=-1"


echo "The 'difok' parameter has been set to 8 in $pwquality_config_file."


##V-238235

# Path to the common-auth configuration file
common_auth_file="/etc/pam.d/common-auth"
# Path to the faillock configuration file
faillock_conf_file="/etc/security/faillock.conf"

# Function to add lines to common-auth for pam_faillock
configure_pam_faillock() {
  echo "Configuring PAM to use pam_faillock..."
  
  # Check if pam_faillock lines already exist
  if ! grep -q "pam_faillock.so" "$common_auth_file"; then
    # Add lines for pam_faillock
    sed -i "/auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc" "$common_auth_file"
    echo "Added pam_faillock configuration to $common_auth_file"
  else
    echo "pam_faillock configuration already exists in $common_auth_file"
  fi
}

# Function to configure faillock options
configure_faillock() {
  echo "Configuring faillock options in $faillock_conf_file..."

  # Ensure the faillock.conf file exists
  if [ ! -f "$faillock_conf_file" ]; then
    touch "$faillock_conf_file"
    echo "Created $faillock_conf_file"
  fi

  # Add or update the faillock options
  {
    echo "audit"
    echo "silent"
    echo "deny = 3"
    echo "fail_interval = 900"
    echo "unlock_time = 0"
  } > "$faillock_conf_file"

  echo "Updated $faillock_conf_file with required options."
}

# Call the functions
configure_pam_faillock
configure_faillock

echo "PAM faillock configuration complete."

##V-238237
# Path to the common-auth configuration file
common_auth_file="/etc/pam.d/common-auth"

# Function to configure pam_faildelay
configure_pam_faildelay() {
  echo "Configuring PAM to enforce a delay after failed login attempts..."
  
  # Check if pam_faildelay line already exists
  if ! grep -q "pam_faildelay.so" "$common_auth_file"; then
    # Add the pam_faildelay line
    echo "auth required pam_faildelay.so delay=4000000" >> "$common_auth_file"
    echo "Added pam_faildelay configuration to $common_auth_file"
  else
    # If it exists, update the line
    sed -i "s/^auth required pam_faildelay.so.*/auth required pam_faildelay.so delay=4000000/" "$common_auth_file"
    echo "Updated pam_faildelay configuration in $common_auth_file"
  fi
}

# Call the function
configure_pam_faildelay

echo "PAM faildelay configuration complete."

##V-238323
# Path to the limits.conf file
limits_conf_file="/etc/security/limits.conf"

# Function to add the maxlogins limit
set_maxlogins_limit() {
  echo "Configuring limits.conf to limit concurrent sessions to 10..."
  
  # Check if the maxlogins line already exists
  if ! grep -q "* hard maxlogins" "$limits_conf_file"; then
    # Add the line to the top of the file
    echo "* hard maxlogins 10" | sudo tee -a "$limits_conf_file" > /dev/null
    echo "Added '* hard maxlogins 10' to $limits_conf_file"
  else
    echo "The limit '* hard maxlogins 10' already exists in $limits_conf_file"
  fi
}

# Call the function
set_maxlogins_limit

echo "Concurrent session limit configuration complete."


#Firefox Policy file location
#“/etc/firefox/policies”

# Define the source and destination paths
source_file="$(dirname "$0")/policies.json"  # Get the path of the script's directory and append policies.json
destination_dir="/etc/firefox/policies"

# Ensure the destination directory exists
if [ ! -d "$destination_dir" ]; then
  echo "Creating directory $destination_dir..."
  mkdir -p "$destination_dir"
fi

# Copy the policies.json file to the destination directory
if [ -f "$source_file" ]; then
  cp "$source_file" "$destination_dir/"
  echo "Copied policies.json to $destination_dir."
else
  echo "Error: policies.json not found in the script's directory."
  exit 1
fi

echo "STIG settings applied. Please reboot the system."

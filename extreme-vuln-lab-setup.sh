#!/bin/bash

# ==============================================================================
# 💀 EXTREMELY VULNERABLE UBUNTU 24.04 LAB - AESTHETIC EDITION 💀
# ==============================================================================

# --- Color Toolkit ---
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
PURPLE='\033[1;35m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

set -e

# Root Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root.${NC}"
   exit 1
fi

clear

# --- Eye-Catching Banner ---
echo -e "${RED}"
echo "██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗"
echo "██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║"
echo "██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}                                            ${WHITE}v1.0 by asepsaepdin8"
echo -e "${NC}"
echo -e "${NC}"
echo -e "      | ${CYAN}Extreme Vulnerability Lab Setup for ${PURPLE}Ubuntu 24.04${NC} |      "
echo -e "${NC}"
echo -e "${GRAY}————————————————————————————————————————————————————————————————${NC}"
echo -e "${NC}"

print_success() {
    echo -e "   ${RED}└─▶${NC} ${YELLOW}SUCCESS:${NC} $1"
}

print_divider() {
    echo -e "${GRAY}-------------------------------------------------------${NC}"
}

# Helper function for headings
print_step() {
    echo -e "\n${PURPLE}⚡ STEP $1 ${NC}"
}

## --- [1/6] Defenses ---
print_step "1/6: Dismantling System Fortifications"
echo -e "    ${CYAN}➤${NC} ${WHITE}Disabling UFW, AppArmor, and ASLR...${NC}"

# Logic Execution
ufw disable > /dev/null 2>&1 || true
systemctl stop apparmor || true
systemctl disable apparmor  > /dev/null 2>&1 || true
echo 0 > /proc/sys/kernel/randomize_va_space
sed -i '/kernel.randomize_va_space/d' /etc/sysctl.conf
echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1

print_success "Defenses Neutralized (Firewall/AppArmor/ASLR)."
print_divider

# --- [2/6] Installations ---
print_step "2/6: Deploying Infrastructure"
echo -e "    ${CYAN}➤${NC} ${WHITE}Installing: Apache, MariaDB, Samba, Docker...${NC}"

# Background process with a simple spinner for eye-catching effect
(
    export DEBIAN_FRONTEND=noninteractive
    apt update -qq > /dev/null 2>&1
    apt install -y -qq \
        openssh-server apache2 libapache2-mod-php php php-mysql php-curl php-gd \
        php-mbstring php-xml php-zip php-intl php-soap php-imagick mariadb-server \
        samba nfs-kernel-server inetutils-telnetd git build-essential vsftpd curl \
        net-tools tcpdump docker.io libcap2-bin python3-pip > /dev/null 2>&1
    pip3 install gdown --break-system-packages --quiet > /dev/null 2>&1
) & 

# Spinner Logic
pid=$!
# Define as an array for proper iteration
spin=('-' '\' '|' '/')

while kill -0 $pid 2>/dev/null; do
    for i in "${spin[@]}"; do
        # Only show spinner if the process is still running
        if ! kill -0 $pid 2>/dev/null; then break; fi
        echo -ne "\r    ${R1}[$i]${NC} ${GRAY}Downloading and configuring packages...${NC}"
        sleep 0.1
    done
done

print_success "Infrastructure Installed Successfully."
print_divider

# --- [3/6] Service Configs ---
print_step "3/6: Sabotaging Service Configurations"

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Vulnerable SSH Services${NC}"

# SSH
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh
# Apache
a2enmod rewrite > /dev/null 2>&1
chmod 777 /var/www/html
systemctl restart apache2

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Vulnerable Samba Services${NC}"

# Samba
if ! grep -q "\[root\]" /etc/samba/smb.conf; then
    cat >> /etc/samba/smb.conf <<EOF
[public]
   path = /var/smb/public
   writable = yes
   guest ok = yes
[root]
   path = /
   writable = yes
   guest ok = yes
EOF
fi
mkdir -p /var/smb/public && chmod 777 /var/smb/public
systemctl restart smbd

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Vulnerable NFS Services${NC}"

# NFS
cat > /etc/exports <<EOF
/ *(rw,sync,no_root_squash,insecure,no_subtree_check)
/home *(rw,sync,no_root_squash,insecure,no_subtree_check)
EOF
exportfs -ra > /dev/null 2>&1
systemctl restart nfs-kernel-server

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Vulnerable FTP Services${NC}"

# FTP
cat > /etc/vsftpd.conf <<EOF
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/var/ftp/pub
chroot_local_user=YES
allow_writeable_chroot=YES
EOF
mkdir -p /var/ftp/pub && chmod -R 777 /var/ftp/pub
systemctl restart vsftpd
print_success "Vulnerable Services Configured."
print_divider

# --- [4/6] Database & Web ---
print_step "4/6: Initializing Web Attack Surface"

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring MariaDB${NC}"

mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'R@v3nSecurity';"
mysql -u root -pR@v3nSecurity -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'password' WITH GRANT OPTION; FLUSH PRIVILEGES;"
mysql -u root -pR@v3nSecurity -e "CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL PRIVILEGES ON *.* TO 'dvwa'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"
sed -i 's/bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring DVWA (Damn Vulnerable Web Application)${NC}"

# DVWA
git clone https://github.com/digininja/DVWA.git /var/www/html/DVWA > /dev/null 2>&1
cp /var/www/html/DVWA/config/config.inc.php.dist /var/www/html/DVWA/config/config.inc.php
chown -R www-data:www-data /var/www/html/DVWA

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Raven-Security Wordpress${NC}"

# WordPress / Raven-Security
gdown https://drive.google.com/uc?id=1DHeaGTh6tWmRjpzMFqwr7DkbsFxp9fY2 --quiet
gdown https://drive.google.com/uc?id=1x6lmF1CtADMkHTtDZ5COaHknHHbhxPjg --quiet
tar -xzvf wordpress_backup2.tar.gz -C /var/www/html/ > /dev/null 2>&1
mysql -u root -pR@v3nSecurity -e "CREATE DATABASE IF NOT EXISTS wordpress; GRANT ALL PRIVILEGES ON wordpress.* TO 'root'@'localhost'; FLUSH PRIVILEGES;" 
mysql -u root -pR@v3nSecurity wordpress < wordpress_database2.sql
mysql -u root -pR@v3nSecurity -e "use wordpress; update wp_users set user_pass = MD5('Pa$$w0rd!') where ID = 1;"
print_success "Database & Attack Surfaces Configured."
print_divider

# --- [5/6] PrivEsc ---
print_step "5/6: Planting Escalation Vectors"

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Classic SUID Binaries${NC}"

gcc -xc -o /usr/local/bin/backup-tool <(echo 'int main(){setuid(0);system("/bin/sh");return 0;}') > /dev/null 2>&1 
chmod 4755 /usr/local/bin/backup-tool

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Python Capabilities${NC}"

cp /usr/bin/python3 /usr/local/bin/python3_cap
setcap cap_setuid+ep /usr/local/bin/python3_cap

echo -e "    ${CYAN}➤${NC} ${WHITE}Configuring Vulnerable Cron Job (Writable by everyone, run by root)${NC}"

echo "* * * * * root /opt/scripts/cleanup.sh" > /etc/cron.d/cleanup
mkdir -p /opt/scripts && echo -e "#!/bin/bash\n/bin/true" > /opt/scripts/cleanup.sh && chmod 777 /opt/scripts/cleanup.sh

#echo -e "    ${CYAN}➤${NC} ${WHITE}Creating Docker Vectors${NC}"

#useradd -m -s /bin/bash student && usermod -aG docker student && echo "student:student123" | chpasswd
print_success "SUID, Python Capabilities, Cron vectors planted."
print_divider

# --- [6/6] Users ---
print_step "6/6: Creating Weak Identities"

echo -e "    ${CYAN}➤${NC} ${WHITE}Creating Vulnerable User${NC}"

useradd -m -s /bin/bash -p "$(openssl passwd -1 password123)" web_admin  > /dev/null 2>&1 
echo "web_admin ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/python3" >> /etc/sudoers
print_success "User 'web_admin' created."
print_divider

# --- Final Summary ---
echo -e "\n${CYAN}======================================================================${NC}"
echo -e "                ${WHITE}LAB DEPLOYMENT SUCCESSFUL${NC}                "
echo -e "${CYAN}======================================================================${NC}"
echo -e "${YELLOW}SYSTEM IP  :${NC} $(hostname -I | awk '{print $1}')"
echo -e "${YELLOW}ROOT PASS  :${NC} R@v3nSecurity"
echo -e "${YELLOW}WEB ADMIN  :${NC} web_admin / password123"
echo -e "${YELLOW}SUID BINS  :${NC} /usr/local/bin/backup-tool"
echo -e "${CYAN}----------------------------------------------------------------------${NC}"
echo -e "${PURPLE}Happy Hacking! Red Team Lab is now ACTIVE.${NC}\n"

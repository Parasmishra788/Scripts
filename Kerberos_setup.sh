#!/bin/bash

################################################################################
# Script Name: setup-kdc.sh

# Description: 
#      script to set up a MIT Kerberos Key Distribution Center (KDC)
#     for Cloudera Manager (CM) environments. 
# Modes:
#     custom            - Interactive mode: Prompt user for configuration.
#     autoconfig - Automated mode: Use default values to set up everything.
#
# Requirements:
#     - Root access on KDC host
#     - JDK installed under /usr/java
#     - Cloudera Manager running and accessible on port 7180
#
# Usage:
#     ./setup-kdc.sh [custom|autoconfig]
################################################################################

# Function to print usage info
function print_usage() {
    echo -e "\nKerberos Setup Tool for Cloudera Manager"
    echo -e "----------------------------------------"
    echo -e "Usage: $0 [custom|autoconfig]\n"
    echo "Options:"
    echo "  custom              Interactive mode - ask for custom REALM, passwords, etc."
    echo "  autoconfig   Automatic setup using defaults:"
    echo "                  REALM = HADOOP.COM"
    echo "                  CM admin = admin / mszurap"
    echo "                  SSH pass = mszurap"
    echo "                  KDC DB pass = cloudera"
    echo "                  Principal pass = cloudera"
    echo ""
    exit 1
}

# === Step 1: Parse the argument ===
if [[ "$1" == "custom" ]]; then
    clear
    echo "Starting interactive KDC setup..."
    read -p "** Enter preferred REALM: " REALM
    read -p "** Enter Cloudera Manager admin username: " ADMIN_USER
    read -sp "** Enter Cloudera Manager admin password: " ADMIN_PASS && echo
    read -sp "** Enter SSH password for root (used for node connections): " SSH_PASS && echo
    read -sp "** Enter password for the KDC master database: " KDC_DB_PASS && echo
    read -sp "** Enter password to be used for Kerberos principals: " PRINC_PASS && echo

elif [[ "$1" == "autoconfig" ]]; then
    echo "Running in automated mode using default values..."
    export REALM="HADOOP.COM"
    export ADMIN_USER="admin"
    export ADMIN_PASS="mszurap"
    export SSH_PASS="mszurap"
    export KDC_DB_PASS="cloudera"
    export PRINC_PASS="cloudera"
else
    print_usage
fi

# === Step 2: Set Host Info ===
export HOSTNAME=$(hostname)
export FQDN=$(nslookup ${HOSTNAME} | awk -F': ' '/^Name:/ {print $2}')
export L_IP=$(nslookup ${HOSTNAME} | awk '/^Address: / {print $2}' | tail -n1)

echo ""
echo "Detected Environment:"
echo "---------------------"
echo "Hostname        : $HOSTNAME"
echo "FQDN            : $FQDN"
echo "Cloudera Realm  : $REALM"
echo "CM Admin User   : $ADMIN_USER"
echo "Local IP        : $L_IP"
echo ""

# === Step 3: Install Required Packages ===
echo "Installing Kerberos and other dependencies..."
yum install -y krb5-libs krb5-server krb5-workstation openldap-clients unzip sshpass \
               lsof screen tcpdump nc curl haveged banner || {
    echo "Package installation failed! Exiting..."
    exit 1
}

# === Step 4: Detect JDK and Setup JCE ===
export JDK=$(find /usr/java -type d -name "jdk*cloudera" | head -n 1)

mkdir -p /root/jce/UnlimitedJCEPolicy

cd /root/jce || exit 1

# -------------------------------
# Handle JCE Deployment Based on JDK Version
# -------------------------------

if [[ ${JDK} == *"1.7.0"* ]]; then
    echo "INFO : Detected Java 1.7 at ${JDK}"
    cd jce
    echo "INFO : Downloading Unlimited JCE Policy for JDK 7..."
    wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" \
        "http://download.oracle.com/otn-pub/java/jce/7/UnlimitedJCEPolicyJDK7.zip"
    unzip -j -o UnlimitedJCEPolicyJDK7.zip -d /root/jce/UnlimitedJCEPolicy
    echo "INFO : JCE Policy for JDK 7 deployed"

elif [[ ${JDK} == *"1.8.0"* ]]; then
    echo "INFO : Detected Java 1.8 at ${JDK}"
    cd jce
    echo "INFO : Downloading Unlimited JCE Policy for JDK 8..."
    wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" \
        "http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip"
    unzip -j -o jce_policy-8.zip -d /root/jce/UnlimitedJCEPolicy
    echo "INFO : JCE Policy for JDK 8 deployed"

elif [[ ${JDK} == *"11."* || ${JDK} == *"17."* || ${JDK} == *"21."* ]]; then
    echo "INFO : Detected Java 11 or newer at ${JDK}"
    echo "INFO : No need to install JCE policy separately — strong crypto is enabled by default."
    sleep 2

else
    echo "WARNING : Unrecognized or unsupported JDK version detected at ${JDK}"
    echo "          Manual verification recommended before proceeding."
    read -p "Press any key to continue without JCE..." foo
fi


# === Step 5: Deploy JCE Locally ===
if [[ -d "UnlimitedJCEPolicy" && -n "$JDK" ]]; then
    echo "Deploying JCE locally..."
    cp -f "${JDK}/jre/lib/security/local_policy.jar" "${JDK}/jre/lib/security/local_policy.jar.orig"
    cp -f "${JDK}/jre/lib/security/US_export_policy.jar" "${JDK}/jre/lib/security/US_export_policy.jar.orig"
    cp -f UnlimitedJCEPolicy/* "${JDK}/jre/lib/security/"
fi

# === Step 6: Configure Kerberos Files ===
echo "Backing up and configuring Kerberos configuration files..."

cp -f /var/kerberos/krb5kdc/kdc.conf{,_orig}
cp -f /var/kerberos/krb5kdc/kadm5.acl{,_orig}
cp -f /etc/krb5.conf{,_orig}

# kdc.conf
cat > /var/kerberos/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88

[realms]
 ${REALM} = {
  acl_file = /var/kerberos/krb5kdc/kadm5.acl
  dict_file = /usr/share/dict/words
  admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
  supported_enctypes = aes256-cts:normal aes128-cts:normal arcfour-hmac:normal
                      des3-hmac-sha1:normal des-cbc-crc:normal des:normal
  max_renewable_life = 7d
  udp_preference_limit = 1
 }
EOF

# krb5.conf
cat > /etc/krb5.conf <<EOF
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 default_realm = ${REALM}
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 default_tgs_enctypes = aes256-cts aes128-cts arcfour-hmac-md5 des-cbc-md5 des-cbc-crc
 default_tkt_enctypes = aes256-cts aes128-cts arcfour-hmac-md5 des-cbc-md5 des-cbc-crc
 permitted_enctypes = aes256-cts aes128-cts arcfour-hmac-md5 des-cbc-md5 des-cbc-crc

[realms]
 ${REALM} = {
  kdc = $FQDN
  admin_server = $FQDN
 }

[domain_realm]
 .cloudera.com = ${REALM}
 cloudera.com = ${REALM}
EOF

# ACL file
cat > /var/kerberos/krb5kdc/kadm5.acl <<EOF
*/admin@${REALM}    *
cloudera-scm@${REALM} *
EOF

# === Step 7: Create KDC DB and Start Services ===
echo "Creating Kerberos database..."
kdb5_util create -s -P "${KDC_DB_PASS}"

echo "Starting Kerberos services..."
systemctl start krb5kdc
systemctl start kadmin
systemctl enable krb5kdc
systemctl enable kadmin

# ===
#!/bin/bash
# -----------------------------------------------------------------------------------
# Script: kerb.sh
# Purpose: Set up a MIT KDC server and deploy Kerberos configuration & JCE policies
# Author: (You can add your name here)
# -----------------------------------------------------------------------------------

# -------------------------------
# Initial Mode Selection Section
# -------------------------------
if [ "$1" == "custom" ] ; then
	clear
	echo "** Setting up a MIT KDC server manually"
	echo "   You'll be prompted to enter all required credentials and configurations."
	echo " "

	# Realm setup
	echo "** Enter your preferred Kerberos REALM (e.g., EXAMPLE.COM):"
	read REALM

	# Cloudera Manager Admin
	echo "** Enter the Cloudera Manager administrator username:"
	read ADMIN_USER
	echo "** Enter the Cloudera Manager administrator password:"
	read ADMIN_PASS

	# SSH Password
	echo "** Enter the root SSH password (used to install components on other cluster nodes):"
	read readsshpass
	export SSH_PASS=${readsshpass}

	# KDC Database Password
	echo "** Specify the KDC master database password:"
	read KDC_DB_PASS

	# Principal Password
	echo "** Enter a default password for the Kerberos principals:"
	read PRINC_PASS

elif [ "$1" == "autoconfig" ] ; then
	# -------------------------------
	# Auto-configuration Defaults
	# -------------------------------
	export REALM=HADOOP.COM
	echo "INFO : Using default realm = $REALM"

	export ADMIN_USER=admin
	echo "INFO : Using default CM admin username = $ADMIN_USER"

	export ADMIN_PASS=mszurap
	echo "INFO : Using default CM admin password"

	export SSH_PASS=mszurap
	echo "INFO : Using default SSH password for cluster"

	export KDC_DB_PASS=cloudera
	echo "INFO : Using default KDC DB password"

	export PRINC_PASS=cloudera
	echo "INFO : Using default principal password"

else 
	# -------------------------------
	# Usage Help Section
	# -------------------------------
	echo "KDC 4 All"
	echo "Quickly create a MIT KDC for Kerberizing Cloudera CDH clusters."
	echo "Run this on the Cloudera Manager (CM) server node."

	echo ""
	echo "Usage:"
	echo "  kerb.sh [custom|autoconfig]"
	echo ""
	echo "Options:"
	echo "  custom               Interactive setup (custom values)"
	echo "  autoconfig    Fully automated setup using predefined values"
	echo ""
	exit 0
fi

# -------------------------------
# Hostname & Network Discovery
# -------------------------------
export HOSTNAME=`hostname`
export FQDN=`nslookup ${HOSTNAME} | grep Name | awk '{print $2}'`
export L_IP=`nslookup ${HOSTNAME} | grep -A1 ${HOSTNAME} | grep Address | awk '{print $2}'`

echo "INFO : Detected machine details:"
echo "INFO : HOSTNAME = ${HOSTNAME}"
echo "INFO : FQDN = ${FQDN}"
echo "INFO : REALM = ${REALM}"
echo "INFO : CM ADMIN USER = ${ADMIN_USER}"

# -------------------------------
# Install Kerberos & Required Tools
# -------------------------------
yum install -y krb5-libs krb5-server krb5-workstation openldap-clients unzip sshpass lsof screen tcpdump nc curl haveged banner

# -------------------------------
# Detect Installed JDK
# -------------------------------
export JDK=`find /usr/java -type d -name "jdk*cloudera"`

if [ ! -d "jce" ]; then
	mkdir -p /root/jce/UnlimitedJCEPolicy
fi

# -------------------------------
# Download and Deploy JCE Policies
# -------------------------------
if [[ ${JDK} == *"1.7.0"* ]]; then
	echo "INFO : Detected Java 1.7 at ${JDK}"
	cd jce
	wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jce/7/UnlimitedJCEPolicyJDK7.zip"
	unzip -j -o UnlimitedJCEPolicyJDK7.zip -d /root/jce/UnlimitedJCEPolicy
	echo "INFO : JCE Policy for JDK 7 deployed"

elif [[ ${JDK} == *"1.8.0"* ]]; then
	echo "INFO : Detected Java 1.8 at ${JDK}"
	cd jce
	wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip"
	unzip -j -o jce_policy-8.zip -d /root/jce/UnlimitedJCEPolicy
	echo "INFO : JCE Policy for JDK 8 deployed"

else
	echo "WARNING : No supported JDK found. Manual intervention may be needed."
	read -p "Press any key to continue without JCE..."
fi

# -------------------------------
# Deploy JCE on Local & Remote Hosts
# -------------------------------
if [ -d "/root/jce/UnlimitedJCEPolicy" ]; then
	echo "INFO : Deploying JCE policies locally"
	cp -f ${JDK}/jre/lib/security/local_policy.jar local_policy.jar.orig
	cp -f ${JDK}/jre/lib/security/US_export_policy.jar US_export_policy.jar.orig
	cp -f /root/jce/UnlimitedJCEPolicy/* ${JDK}/jre/lib/security/

	echo "INFO : Deploying JCE to other nodes in cluster"
	# Install Kerberos libs on other hosts and deploy JCE
	curl -s -u ${ADMIN_USER}:${ADMIN_PASS} -N http://${FQDN}:7180/api/v1/hosts | grep ipAddr | grep -v ${L_IP} \
	| awk -F"\"" '{printf "ssh root@%s yum install -y krb5-libs krb5-workstation openldap-clients unzip\n", $4}' | sh

	curl -s -u ${ADMIN_USER}:${ADMIN_PASS} -N http://${FQDN}:7180/api/v1/hosts | grep ipAddr | grep -v ${L_IP} \
	| awk -F"\"" '{printf "ssh root@%s mkdir -p /root/jce/UnlimitedJCEPolicy; scp /root/jce/UnlimitedJCEPolicy/* root@%s:/root/jce/UnlimitedJCEPolicy/;\n", $4, $4}' | sh

	curl -s -u ${ADMIN_USER}:${ADMIN_PASS} -N http://${FQDN}:7180/api/v1/hosts | grep ipAddr | grep -v ${L_IP} \
	| awk -F"\"" -v JDK="$JDK" '{printf "ssh root@%s cp -f $JDK/jre/lib/security/local_policy.jar $JDK/jre/lib/security/local_policy.jar.orig; cp -f /root/jce/UnlimitedJCEPolicy/local_policy.jar $JDK/jre/lib/security/local_policy.jar;\n", $4}' | sh

	curl -s -u ${ADMIN_USER}:${ADMIN_PASS} -N http://${FQDN}:7180/api/v1/hosts | grep ipAddr | grep -v ${L_IP} \
	| awk -F"\"" -v JDK="$JDK" '{printf "ssh root@%s cp -f $JDK/jre/lib/security/US_export_policy.jar $JDK/jre/lib/security/US_export_policy.jar.orig; cp -f /root/jce/UnlimitedJCEPolicy/US_export_policy.jar $JDK/jre/lib/security/US_export_policy.jar;\n", $4}' | sh

	echo "INFO : JCE policies deployed on all cluster nodes"
fi

# -------------------------------
# Backup Original Kerberos Config
# -------------------------------
cp -f /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kdc.conf_orig
cp -f /var/kerberos/krb5kdc/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl_orig
cp -f /etc/krb5.conf /etc/krb5.conf_orig

# -------------------------------
# Write KDC Configuration Files
# -------------------------------
# KDC configuration
cat <<EOF > /var/kerberos/krb5kdc/kdc.conf
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88

[realms]
${REALM} = {
 acl_file = /var/kerberos/krb5kdc/kadm5.acl
 dict_file = /usr/share/dict/words
 admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
 supported_enctypes = aes256-cts:normal aes128-cts:normal arcfour-hmac:normal des3-hmac-sha1:normal des-cbc-crc:normal des:normal des:v4 des:norealm des:onlyrealm des:afs3
 max_renewable

#!/bin/bash


log_message() {
    echo "$(date +"%d/%m/%Y %H:%M:%S") $1"
}


check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_message "ERROR: This script must be run as root"
        exit 1
    fi
}


change_wazuh_password() {
    log_message "INFO: Changing Wazuh admin password..."
    
    # Define variables
    WAZUH_TOOL="wazuh-passwords-tool.sh"
    ADMIN_USER="admin"
    ADMIN_PASSWORD="Admin@123*" # Password that meets requirements
    
    # Check if the Wazuh passwords tool exists in the current directory
    if [ ! -f "$WAZUH_TOOL" ]; then
        # Check if it exists in the Wazuh indexer directory
        if [ -f "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/$WAZUH_TOOL" ]; then
            log_message "INFO: Using existing Wazuh passwords tool from Wazuh indexer."
            WAZUH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/$WAZUH_TOOL"
        else
            # Download the tool
            log_message "INFO: Downloading Wazuh passwords tool..."
            if ! curl -so "$WAZUH_TOOL" https://packages.wazuh.com/4.11/wazuh-passwords-tool.sh; then
                log_message "ERROR: Failed to download the Wazuh passwords tool."
                return 1
            fi
            
            # Make it executable
            chmod +x "$WAZUH_TOOL"
        fi
    fi
    
    # Change the admin password
    
    if ! bash "$WAZUH_TOOL" -u "$ADMIN_USER" -p "$ADMIN_PASSWORD"; then

        return 1
    fi
    
    
    log_message "WARNING: If you're using a distributed environment, remember to update the password in other components (Wazuh dashboard, Filebeat nodes, etc.)."
    
    return 0
}


install_wazuh_official() {
    log_message "INFO: Starting Wazuh installation using official installer..."
    

    if [ -d "/var/ossec" ]; then
        log_message "INFO: Wazuh appears to be already installed"
        read -p "Do you want to reinstall Wazuh? (y/n, default: n): " REINSTALL_WAZUH
        REINSTALL_WAZUH=${REINSTALL_WAZUH:-n}
        
        if [[ ! "$REINSTALL_WAZUH" =~ ^[Yy]$ ]]; then
            log_message "INFO: Skipping Wazuh installation"
            return 0
        else
            log_message "INFO: Removing existing Wazuh installation is recommended."
            log_message "INFO: Please remove it manually or use 'wazuh-uninstall.sh' if available."
            read -p "Continue with installation anyway? (y/n, default: n): " CONTINUE
            CONTINUE=${CONTINUE:-n}
            
            if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
                log_message "INFO: Exiting as requested by user"
                exit 0
            fi
        fi
    fi
    

    log_message "INFO: Downloading the official Wazuh installer..."
    curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
    
    if [ ! -f "wazuh-install.sh" ]; then
        log_message "ERROR: Failed to download Wazuh installer"
        exit 1
    fi
    

    chmod +x wazuh-install.sh
    

    log_message "INFO: Running Wazuh installer..."
    ./wazuh-install.sh -a
    

    if [ ! -d "/var/ossec" ]; then
        log_message "ERROR: Wazuh installation failed"
        exit 1
    fi
    
    log_message "INFO: Wazuh installation completed successfully"
    

    sleep 10
}


check_disk_space() {
    log_message "INFO: Checking disk space..."
    
    ROOT_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$ROOT_USAGE" -gt 80 ]; then
        log_message "WARNING: Root partition is at ${ROOT_USAGE}% capacity. This may cause issues during installation."
        read -p "Do you want to continue? (y/n, default: n): " CONTINUE
        CONTINUE=${CONTINUE:-n}
        
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            log_message "INFO: Exiting as requested by user"
            exit 0
        fi
        
        log_message "INFO: Continuing with installation despite low disk space"
    else
        log_message "INFO: Disk space is sufficient at ${ROOT_USAGE}%"
    fi
}


install_prerequisites() {
    log_message "INFO: Installing prerequisites..."
    

    apt-get update
    

    apt-get install -y curl wget git vim apt-transport-https gnupg software-properties-common unzip
    
    log_message "INFO: Prerequisites installed successfully"
}


install_opensearch_logstash() {
    log_message "INFO: Starting OpenSearch Logstash installation..."
    

    if [ -d "/root/logstash-8.9.0" ]; then
        log_message "INFO: OpenSearch Logstash is already installed"
        read -p "Do you want to reinstall OpenSearch Logstash? (y/n, default: n): " REINSTALL_LOGSTASH
        REINSTALL_LOGSTASH=${REINSTALL_LOGSTASH:-n}
        
        if [[ ! "$REINSTALL_LOGSTASH" =~ ^[Yy]$ ]]; then
            log_message "INFO: Skipping OpenSearch Logstash installation"
            return 0
        else
            log_message "INFO: Removing existing OpenSearch Logstash installation"
            systemctl stop logstash || true
            rm -rf /root/logstash-8.9.0
            rm -f /etc/systemd/system/logstash.service
        fi
    fi
    

    LOGSTASH_VERSION="8.9.0"
    LOGSTASH_TARBALL="logstash-oss-with-opensearch-output-plugin-${LOGSTASH_VERSION}-linux-x64.tar.gz"
    

    log_message "INFO: Downloading OpenSearch Logstash tarball..."
    wget -q "https://artifacts.opensearch.org/logstash/${LOGSTASH_TARBALL}" -O "${LOGSTASH_TARBALL}"
    
    if [ ! -f "${LOGSTASH_TARBALL}" ]; then
        log_message "ERROR: Failed to download OpenSearch Logstash tarball"
        exit 1
    fi
    

    log_message "INFO: Extracting OpenSearch Logstash tarball..."
    tar -xzf "${LOGSTASH_TARBALL}"
    
    if [ ! -d "logstash-${LOGSTASH_VERSION}" ]; then
        log_message "ERROR: Failed to extract OpenSearch Logstash tarball"
        exit 1
    fi
    

    mv "logstash-${LOGSTASH_VERSION}" /root/
    

    log_message "INFO: Installing Logstash plugins..."
    /root/logstash-8.9.0/bin/logstash-plugin install logstash-filter-dns
    
    log_message "INFO: OpenSearch Logstash installation completed successfully"
    log_message "INFO: Extracted to /root/logstash-${LOGSTASH_VERSION}"
}


configure_logstash_service() {
    log_message "INFO: Configuring Logstash as a service..."
    

    cat > /etc/systemd/system/logstash.service << 'EOF'
[Unit]
Description=Logstash Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/root/logstash-8.9.0/bin/logstash -f /etc/logstash/synlite_suricata/conf.d/
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=logstash
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF


    mkdir -p /etc/systemd/system/logstash.service.d
    

    systemctl daemon-reload
    

    systemctl enable logstash
    
    log_message "INFO: Logstash service configured successfully"
}


configure_elasticsearch_vars() {
    log_message "INFO: Configuring Elasticsearch environment variables..."
    

    mkdir -p /etc/systemd/system/logstash.service.d/
    
    cat > /etc/systemd/system/logstash.service.d/synlite_suricata.conf << 'EOF'

Environment="SYNLITE_SURICATA_ES_HOST=127.0.0.1"
Environment="SYNLITE_SURICATA_ES_USER=admin"
Environment="SYNLITE_SURICATA_ES_PASSWD=Admin@123*"
EOF
    

    cat > /etc/profile.d/synlite_suricata.sh << 'EOF'

export SYNLITE_SURICATA_ES_HOST=127.0.0.1
export SYNLITE_SURICATA_ES_USER=admin
export SYNLITE_SURICATA_ES_PASSWD=Admin@123*
EOF
    

    chmod +x /etc/profile.d/synlite_suricata.sh
    
    log_message "INFO: Elasticsearch environment variables configured successfully"
}


install_suricata() {
    log_message "INFO: Installing Suricata..."
    

    log_message "INFO: Adding Suricata repository..."
    add-apt-repository ppa:oisf/suricata-stable -y
    apt-get update
    

    log_message "INFO: Installing Suricata package..."
    apt-get install -y suricata
    

    log_message "INFO: Configuring log rotation for Suricata..."
    cat > /etc/logrotate.d/suricata << 'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        if [ -e /var/run/suricata.pid ]; then
            kill -USR2 $(cat /var/run/suricata.pid)
        fi
    endscript
}
EOF
    

    update_suricata_rules
    

    systemctl enable suricata
    
    log_message "INFO: Suricata installed successfully"
}


update_suricata_rules() {
    log_message "INFO: Downloading and extracting Emerging Threats ruleset..."
    

    mkdir -p /etc/suricata/rules
    mkdir -p /var/log/suricata
    chmod 755 /var/log/suricata
    

    cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
    
    if [ ! -f /tmp/emerging.rules.tar.gz ]; then
        log_message "ERROR: Failed to download Emerging Threats ruleset"
        return 1
    fi
    

    tar -xzf emerging.rules.tar.gz 
    cp -f rules/*.rules /etc/suricata/rules/ || true
    chmod 640 /etc/suricata/rules/*.rules || true
    
    log_message "INFO: Configuring Suricata..."
    

    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [ -z "$PRIMARY_INTERFACE" ]; then
        log_message "WARNING: Could not determine primary interface. Using 'eth0' as default."
        PRIMARY_INTERFACE="eth0"
    fi
    

    UBUNTU_IP=$(ip -4 addr show ${PRIMARY_INTERFACE} | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -z "$UBUNTU_IP" ]; then
        log_message "WARNING: Could not determine IP address. Using '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12' as HOME_NET."
        UBUNTU_IP="[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    fi
    

    if [ -f "/etc/suricata/suricata.yaml" ]; then
        cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
    fi
    

    sed -i "s/  HOME_NET: \"\[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12\]\"/  HOME_NET: \"${UBUNTU_IP}\"/" /etc/suricata/suricata.yaml
    sed -i 's|default-rule-path: /var/lib/suricata/rules|default-rule-path: /etc/suricata/rules|' /etc/suricata/suricata.yaml
    

    if grep -q "rule-files:" /etc/suricata/suricata.yaml; then

        sed -i '/rule-files:/,/^$/ {/^$/! {/rule-files:/! d}}' /etc/suricata/suricata.yaml
        sed -i '/rule-files:/ a \  - "*.rules"' /etc/suricata/suricata.yaml
    else

        echo -e "\nrule-files:\n  - \"*.rules\"" >> /etc/suricata/suricata.yaml
    fi
    

    sed -i 's/  enabled: no/  enabled: yes/' /etc/suricata/suricata.yaml
    

    sed -i "s/  - interface: eth0/  - interface: ${PRIMARY_INTERFACE}/" /etc/suricata/suricata.yaml
    
    log_message "INFO: Suricata rules updated and configuration completed for interface ${PRIMARY_INTERFACE}"
}


install_synesis_lite_suricata() {
    log_message "INFO: Installing Synesis Lite Suricata components..."
    

    log_message "INFO: Cloning Synesis Lite Suricata repository..."
    cd ~
    git clone https://github.com/shakeelzaman7/synesis_lite_suricata
    
    if [ ! -d "$HOME/synesis_lite_suricata" ]; then
        log_message "ERROR: Failed to clone Synesis Lite Suricata repository"
        return 1
    fi
    

    log_message "INFO: Copying Logstash pipeline configuration..."
    cd ~/synesis_lite_suricata/logstash
    mkdir -p /etc/logstash/
    cp -r synlite_suricata /etc/logstash/
    

    cd ..
    cp -r logstash.service.d /etc/systemd/system/
    

    if [ -d "profile.d" ]; then
        cp profile.d/* /etc/profile.d/
    fi
    

    log_message "INFO: Installing Logstash DNS filter plugin..."
    /root/logstash-8.9.0/bin/logstash-plugin install logstash-filter-dns
    

    cat > /etc/logstash/pipelines.yml << 'EOF'
- pipeline.id: synlite_suricata
  path.config: "/etc/logstash/synlite_suricata/conf.d/*.conf"
EOF
    
    log_message "INFO: Synesis Lite Suricata components installed successfully"
}


configure_wazuh_suricata_monitoring() {
    log_message "INFO: Configuring Wazuh to monitor Suricata logs..."
    

    if [ ! -d "/var/ossec" ]; then
        log_message "ERROR: Wazuh is not installed. Cannot configure Suricata monitoring."
        return 1
    fi
    

    if [ ! -f "/var/ossec/etc/ossec.conf.bak" ]; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    fi
    

    if grep -q "/var/log/suricata/eve.json" /var/ossec/etc/ossec.conf; then
        log_message "INFO: Suricata log monitoring is already configured in Wazuh"
        return 0
    fi
    

    log_message "INFO: Adding Suricata log monitoring to Wazuh configuration..."
    

    if grep -q "<localfile>" /var/ossec/etc/ossec.conf; then

        sed -i '/<\/localfile>/a \  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/suricata/eve.json</location>\n  </localfile>' /var/ossec/etc/ossec.conf
    else

        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/suricata/eve.json</location>\n  </localfile>' /var/ossec/etc/ossec.conf
    fi
    

    log_message "INFO: Restarting Wazuh manager to apply configuration changes..."
    systemctl restart wazuh-manager
    

    sleep 5
    if systemctl is-active --quiet wazuh-manager; then
        log_message "INFO: Wazuh manager restarted successfully"
    else
        log_message "ERROR: Failed to restart Wazuh manager. Check configuration for errors."
        log_message "INFO: You can check the status with: systemctl status wazuh-manager"
        return 1
    fi
    
    log_message "INFO: Wazuh configured to monitor Suricata logs successfully"
    return 0
}


install_filebeat() {
    log_message "INFO: Setting up Filebeat for Suricata..."
    
    # Skip installation - assume Filebeat is already installed
    log_message "INFO: Using existing Filebeat installation"
    
    log_message "INFO: Configuring dedicated Filebeat instance for Suricata..."
    
    # Backup original Filebeat configuration if it exists
    if [ -f "/etc/filebeat/filebeat.yml" ]; then
        log_message "INFO: Backing up original Filebeat configuration"
        cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak
    fi
    
    # Create a dedicated Filebeat instance for Suricata
    log_message "INFO: Creating dedicated Filebeat-Suricata instance..."
    
    # Copy the entire Filebeat configuration directory
    log_message "INFO: Copying Filebeat configuration files..."
    cp -r /etc/filebeat /etc/filebeat-suricata
    
    # Copy and modify the systemd service file
    log_message "INFO: Setting up Filebeat-Suricata systemd service..."
    if [ -f "/etc/systemd/system/filebeat.service" ]; then
        cp /etc/systemd/system/filebeat.service /etc/systemd/system/filebeat-suricata.service
        # Update the service file to point to the new configuration
        sed -i 's|-c /etc/filebeat/filebeat.yml|-c /etc/filebeat-suricata/filebeat.yml|g' /etc/systemd/system/filebeat-suricata.service
    else
        # Create the service file if the original doesn't exist
        cat > /etc/systemd/system/filebeat-suricata.service << 'EOL'
[Unit]
Description=Filebeat Suricata Forwarder
After=network.target
[Service]
ExecStart=/usr/share/filebeat/bin/filebeat \
  -c /etc/filebeat-suricata/filebeat.yml \
  --path.data /var/lib/filebeat-suricata \
  --path.logs /var/log/filebeat-suricata \
  --path.home /usr/share/filebeat-suricata \
  -E seccomp.enabled=false
Restart=always
User=root
Group=root
[Install]
WantedBy=multi-user.target
EOL
    fi
    
    # Reload systemd configuration
    log_message "INFO: Reloading systemd configuration..."
    systemctl daemon-reload
    
    # Configure the dedicated Filebeat for Suricata
    log_message "INFO: Configuring Filebeat-Suricata for Suricata logs..."
    cat > /etc/filebeat-suricata/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    fields:
      event.type: suricata
 
output.logstash:
  hosts: ["127.0.0.1:5044"]
 
seccomp.enabled: false
EOF
    
    # Enable the dedicated Filebeat-Suricata service
    log_message "INFO: Enabling Filebeat-Suricata service..."
    systemctl enable filebeat-suricata.service
    
    log_message "INFO: Dedicated Filebeat for Suricata configured successfully"
    log_message "INFO: You can check its status with: systemctl status filebeat-suricata"


systemctl daemon-reexec
systemctl daemon-reload

}

fix_common_issues() {
    log_message "INFO: Checking for and fixing common issues..."
    

    if [ ! -d "/var/log/suricata" ]; then
        mkdir -p /var/log/suricata
    fi
    chmod 755 /var/log/suricata
    

    if [ ! -f "/var/log/suricata/eve.json" ]; then
        touch /var/log/suricata/eve.json
    fi
    chmod 640 /var/log/suricata/eve.json
    

    sysctl -w net.ipv4.ip_local_port_range="5045 65535" || true
    

    if command -v ufw &> /dev/null; then
        log_message "INFO: Configuring firewall rules for required services..."
        ufw allow 1514/tcp || true # Wazuh agent connections
        ufw allow 1515/tcp || true # Wazuh agent enrollment
        ufw allow 514/udp || true  # Syslog 
        ufw allow 5044/tcp || true # Logstash Beats input
    fi
    
    log_message "INFO: Common issues fixed"
}

update_logstash() {
    CONFIG_FILE="/root/logstash-8.9.0/config/jvm.options"
    
    # Find file if not in expected location
    if [ ! -f "$CONFIG_FILE" ]; then
        CONFIG_FILE=$(find / -name "jvm.options" -path "*logstash-8.9.0/config*" 2>/dev/null)
        [ -z "$CONFIG_FILE" ] && return 1
    fi
    
    # Update memory settings using exact pattern matching
    sed -i 's/-Xms1g/-Xms4g/g' "$CONFIG_FILE"
    sed -i 's/-Xmx1g/-Xmx4g/g' "$CONFIG_FILE"
    
    # Install opensearch plugin
    /root/logstash-8.9.0/bin/logstash-plugin install logstash-output-opensearch
}


start_services() {
    log_message "INFO: Starting all services..."
    

    systemctl daemon-reload
    

    log_message "INFO: Ensuring Wazuh manager is running..."
    systemctl start wazuh-manager
    sleep 5
    systemctl status wazuh-manager --no-pager
    

    log_message "INFO: Starting Suricata..."
    systemctl start suricata
    sleep 5
    systemctl status suricata --no-pager
    

    log_message "INFO: Starting Logstash..."
    systemctl start logstash
    sleep 5
    systemctl status logstash --no-pager
    

    log_message "INFO: Starting Filebeat..."
    systemctl start filebeat
    sleep 5
    systemctl status filebeat --no-pager

    sleep 5
    systemctl restart filebeat-suricata

    sleep 5
    systemctl restart suricata
    
    log_message "INFO: All services started"
}


print_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    log_message "INFO: Installation and configuration completed"
    log_message "INFO: Service status summary:"
    

    WAZUH_STATUS=$(systemctl is-active wazuh-manager)
    log_message "INFO: Wazuh: ${WAZUH_STATUS}"
    

    LOGSTASH_STATUS=$(systemctl is-active logstash)
    log_message "INFO: Logstash: ${LOGSTASH_STATUS}"
    

    SURICATA_STATUS=$(systemctl is-active suricata)
    log_message "INFO: Suricata: ${SURICATA_STATUS}"
    

    FILEBEAT_STATUS=$(systemctl is-active filebeat)
    log_message "INFO: Filebeat: ${FILEBEAT_STATUS}"
    
    log_message "INFO: Wazuh is monitoring the system and Suricata logs"
    log_message "INFO: Suricata is monitoring network traffic on the primary interface"
    log_message "INFO: Logstash is configured to collect and process logs"
    log_message "INFO: Filebeat is configured to send logs to Logstash"
    

    cat > ~/security_stack_install_info.txt << EOF
Security Stack Installation Information
======================================
Date: $(date)
Server IP: ${SERVER_IP}

Services Status
--------------
Wazuh: ${WAZUH_STATUS:-Not installed}
Logstash: ${LOGSTASH_STATUS:-Not installed}
Suricata: ${SURICATA_STATUS:-Not installed}
Filebeat: ${FILEBEAT_STATUS:-Not installed}

Configuration Paths
------------------
Wazuh: /var/ossec/etc
Logstash: /root/logstash-8.9.0 and /etc/logstash
Suricata: /etc/suricata
Filebeat: /etc/filebeat

Log Locations
------------
Wazuh: /var/ossec/logs/alerts/alerts.json
Suricata: /var/log/suricata/eve.json
Logstash: /var/log/logstash/logstash-plain.log
Filebeat: /var/log/filebeat/filebeat

To view Suricata alerts in real-time:
$ tail -f /var/log/suricata/eve.json | grep -A 10 "event_type":"alert"

To access the Wazuh dashboard:
https://${SERVER_IP}
Username: admin
Password: Admin@123*
EOF
    
    log_message "INFO: Installation summary saved to ~/security_stack_install_info.txt"
    
    log_message "INFO: Access the Wazuh dashboard at: https://${SERVER_IP}"

    log_message "INFO: To add agents to this Wazuh manager:"
    log_message "INFO: 1. On the Wazuh dashboard, go to Agents > Deploy new agent"
    log_message "INFO: 2. Follow the instructions for your operating system"
    log_message "INFO: 3. Or use command line: /var/ossec/bin/manage_agents"
}


install_security_stack() {
    log_message "INFO: Starting installation of security stack components..."
    

    install_prerequisites
    

    install_opensearch_logstash
    

    configure_logstash_service
    

    install_suricata
    

    install_synesis_lite_suricata
    

    configure_elasticsearch_vars
    

    configure_wazuh_suricata_monitoring
    

    install_filebeat
    

    fix_common_issues

    update_logstash    

    start_services
    

    print_summary
}


main() {
    log_message "INFO: Starting security stack installation with password change"
    

    check_root
    

    check_disk_space
    

    install_wazuh_official
    
    # Change Wazuh password after installation
    if change_wazuh_password; then
        log_message "INFO: Wazuh password changed successfully"
    else
        log_message "ERROR: Failed to change Wazuh password, but continuing with installation"
    fi
    

    install_security_stack
    log_message "INFO: Complete security stack installation finished successfully"
}


main
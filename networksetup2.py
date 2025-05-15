#!/usr/bin/env python3
"""
Linux Server and Client Configuration Script

This script automates the setup of a Linux server or client with:
- SELinux configuration
- Firewall management
- Network interface configuration
- Hostname setup
- /etc/hosts file updates
"""

import os
import subprocess
import sys
from shutil import which
from datetime import datetime

def run_command(cmd, sudo=False):
    """Execute a shell command and return its output."""
    if sudo:
        cmd = ['sudo'] + cmd.split()
    else:
        cmd = cmd.split()
    
    try:
        result = subprocess.run(
            cmd, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True  # Changed from text=True for Python 3.6 compatibility
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(cmd)}")
        print(f"Error: {e.stderr.strip() if hasattr(e, 'stderr') else str(e)}")
        return None

def check_root():
    """Check if the script is being run as root."""
    if os.geteuid() != 0:
        print("This script must be run as root or with sudo privileges.")
        sys.exit(1)

def check_distro():
    """Check if the distribution is supported (RHEL/CentOS/Fedora)."""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read()
            if 'centos' in content.lower() or 'rhel' in content.lower() or 'fedora' in content.lower():
                return True
    except FileNotFoundError:
        pass
    print("This script is designed for RHEL/CentOS/Fedora distributions.")
    sys.exit(1)

def disable_selinux():
    """Disable SELinux based on user choice."""
    print("\n=== SELinux Configuration ===")
    
    # Check current SELinux status first
    current_status = run_command("getenforce")
    print(f"Current SELinux status: {current_status}")
    
    if current_status and current_status.lower() == 'disabled':
        print("SELinux is already disabled.")
        return
    
    choice = input("Do you want to disable SELinux? (y/n): ").strip().lower()
    
    if choice == 'y':
        # Check if config file already has SELINUX=disabled
        with open('/etc/selinux/config', 'r') as f:
            selinux_config = f.read()
        
        if 'SELINUX=disabled' in selinux_config:
            print("SELinux is already configured to be disabled in /etc/selinux/config")
            print("You may need to reboot for changes to take effect.")
            return
            
        # Create backup of SELinux config
        backup_file = f"/etc/selinux/config.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_command(f"cp /etc/selinux/config {backup_file}", sudo=True)
        print(f"Created backup of SELinux config at {backup_file}")
        
        # Edit SELinux config file
        with open('/etc/selinux/config', 'r') as f:
            lines = f.readlines()
        
        with open('/etc/selinux/config', 'w') as f:
            for line in lines:
                if line.startswith('SELINUX='):
                    f.write('SELINUX=disabled\n')
                else:
                    f.write(line)
        
        print("SELinux will be disabled after reboot. You may need to reboot for changes to take effect.")
    else:
        print("SELinux will remain enabled.")

def manage_firewall():
    """Stop and disable firewalld service or continue if already disabled."""
    print("\n=== Firewall Configuration ===")
    
    # Check if firewalld is installed
    firewalld_installed = run_command("rpm -q firewalld")
    if not firewalld_installed:
        print("Firewalld is not installed. Continuing to next configuration...")
        return
    
    # Check current status
    firewalld_status = run_command("systemctl is-active firewalld")
    if not firewalld_status:
        firewalld_status = "inactive"
    
    firewalld_enabled_check = run_command("systemctl is-enabled firewalld")
    firewalld_enabled = firewalld_enabled_check and "enabled" in firewalld_enabled_check
    
    print(f"Current firewalld status: {'Active' if firewalld_status == 'active' else 'Inactive'}")
    print(f"Firewalld enabled on boot: {'Yes' if firewalld_enabled else 'No'}")
    
    # If firewall is already stopped and disabled, skip to next step
    if firewalld_status != 'active' and not firewalld_enabled:
        print("Firewalld is already stopped and disabled. Continuing to next configuration...")
        return
    
    choice = input("Do you want to disable firewalld? (y/n): ").strip().lower()
    
    if choice == 'y':
        try:
            if firewalld_status == 'active':
                print("Stopping firewalld service...")
                run_command("systemctl stop firewalld", sudo=True)
            
            if firewalld_enabled:
                print("Disabling firewalld from starting on boot...")
                run_command("systemctl disable firewalld", sudo=True)
            
            # Verify changes
            new_status = run_command("systemctl is-active firewalld")
            if not new_status:
                new_status = "inactive"
                
            new_enabled_check = run_command("systemctl is-enabled firewalld")
            new_enabled = new_enabled_check and "enabled" in new_enabled_check
            
            print("\nFinal firewall status:")
            print(f"Running: {'Yes' if new_status == 'active' else 'No'}")
            print(f"Enabled: {'Yes' if new_enabled else 'No'}")
            
        except Exception as e:
            print(f"Error modifying firewall: {str(e)}")
    else:
        print("No changes made to firewall configuration.")
    
    print("Continuing to next configuration...")

def restart_network_manager():
    """Restart NetworkManager service."""
    print("\nRestarting NetworkManager service...")
    run_command("systemctl restart NetworkManager", sudo=True)
    print("NetworkManager service restarted.")

def get_network_info(connection_type):
    """Get network configuration details from user."""
    print(f"\n=== {connection_type.upper()} Network Configuration ===")
    
    config = {
        'connection_type': connection_type,
        'is_server': False,
        'color_type': input(f"Enter color type for {connection_type} network (e.g., RED): ").strip(),
        'interface_name': input(f"Enter interface name (e.g., ens224): ").strip(),
        'use_dhcp': False,
    }
    
    if connection_type.lower() == 'lan':
        config['is_server'] = input("Is this a server? (y/n): ").strip().lower() == 'y'
        config['use_dhcp'] = input("Use DHCP? (y/n): ").strip().lower() == 'y'
        
        if not config['use_dhcp']:
            config['ip_address'] = input("Enter IP address (e.g., 172.16.31.25): ").strip()
            config['netmask'] = input("Enter netmask (e.g., 255.255.0.0): ").strip()
            config['network'] = input("Enter network address (e.g., 172.16.0.0): ").strip()
            config['broadcast'] = input("Enter broadcast address (e.g., 172.16.255.255): ").strip()
    
    return config

def create_network_config(config):
    """Create network configuration file based on user input."""
    if config['connection_type'].lower() == 'lan':
        if config['use_dhcp']:
            return f"""# {config['color_type']} NETWORK {'SERVER' if config['is_server'] else 'CLIENT'}
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=dhcp
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=eui64
NAME={config['interface_name']}
DEVICE={config['interface_name']}
ONBOOT=yes
"""
        else:
            return f"""# {config['color_type']} NETWORK {'SERVER' if config['is_server'] else 'CLIENT'}
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
IPADDR={config['ip_address']}
NETMASK={config['netmask']}
NETWORK={config['network']}
BROADCAST={config['broadcast']}
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=eui64
NAME={config['interface_name']}
DEVICE={config['interface_name']}
ONBOOT=yes
"""
    else:  # NAT connection
        return f"""# NAT Connection
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=dhcp
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=eui64
NAME={config['interface_name']}
DEVICE={config['interface_name']}
ONBOOT=yes
"""

def configure_network_interfaces():
    """Configure LAN and NAT network interfaces."""
    print("\n=== Network Interface Configuration ===")
    
    # First check if interfaces exist
    interfaces = run_command("ls /sys/class/net").split()
    print(f"Available interfaces: {', '.join(interfaces)}")
    
    # Configure LAN interface
    print("\n=== LAN Network Configuration ===")
    lan_config = get_network_info('LAN')
    
    # Verify interface exists
    if lan_config['interface_name'] not in interfaces:
        print(f"Warning: Interface {lan_config['interface_name']} not found!")
        choice = input("Continue anyway? (y/n): ").strip().lower()
        if choice != 'y':
            lan_config = None
        else:
            print(f"Proceeding with non-existent interface {lan_config['interface_name']}")
    else:
        # Check if config file already exists
        lan_config_path = f"/etc/sysconfig/network-scripts/ifcfg-{lan_config['interface_name']}"
        if os.path.exists(lan_config_path):
            print(f"Config file {lan_config_path} already exists.")
            with open(lan_config_path, 'r') as f:
                print("Current configuration:")
                print(f.read())
            choice = input("Overwrite? (y/n): ").strip().lower()
            if choice != 'y':
                print("Skipping LAN interface configuration.")
                lan_config = None
    
    # Configure NAT interface
    print("\n=== NAT Network Configuration ===")
    nat_config = get_network_info('NAT')
    
    # Verify interface exists
    if nat_config['interface_name'] not in interfaces:
        print(f"Warning: Interface {nat_config['interface_name']} not found!")
        choice = input("Continue anyway? (y/n): ").strip().lower()
        if choice != 'y':
            nat_config = None
        else:
            print(f"Proceeding with non-existent interface {nat_config['interface_name']}")
    else:
        # Check if config file already exists
        nat_config_path = f"/etc/sysconfig/network-scripts/ifcfg-{nat_config['interface_name']}"
        if os.path.exists(nat_config_path):
            print(f"Config file {nat_config_path} already exists.")
            with open(nat_config_path, 'r') as f:
                print("Current configuration:")
                print(f.read())
            choice = input("Overwrite? (y/n): ").strip().lower()
            if choice != 'y':
                print("Skipping NAT interface configuration.")
                nat_config = None
    
    # Generate and write configurations for interfaces that passed verification
    if lan_config:
        lan_config_content = create_network_config(lan_config)
        lan_config_path = f"/etc/sysconfig/network-scripts/ifcfg-{lan_config['interface_name']}"
        
        # Create backup before overwriting
        if os.path.exists(lan_config_path):
            backup_path = f"{lan_config_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_command(f"cp {lan_config_path} {backup_path}", sudo=True)
            print(f"Created backup of LAN config at {backup_path}")
        
        with open(lan_config_path, 'w') as f:
            f.write(lan_config_content)
        print(f"LAN configuration written to {lan_config_path}")
    
    if nat_config:
        nat_config_content = create_network_config(nat_config)
        nat_config_path = f"/etc/sysconfig/network-scripts/ifcfg-{nat_config['interface_name']}"
        
        # Create backup before overwriting
        if os.path.exists(nat_config_path):
            backup_path = f"{nat_config_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            run_command(f"cp {nat_config_path} {backup_path}", sudo=True)
            print(f"Created backup of NAT config at {backup_path}")
        
        with open(nat_config_path, 'w') as f:
            f.write(nat_config_content)
        print(f"NAT configuration written to {nat_config_path}")
    
    return lan_config, nat_config

def set_hostname(lan_config):
    """Set system hostname based on user input."""
    print("\n=== Hostname Configuration ===")
    
    user_id = input("Enter user ID (e.g., bouw0026): ").strip()
    os_type = 'srv' if lan_config['is_server'] else 'clt'
    example_num = input("Enter example number (e.g., 25): ").strip()
    
    hostname = f"{user_id}-{os_type}.example{example_num}.lab"
    print(f"Setting hostname to: {hostname}")
    
    run_command(f"hostnamectl set-hostname {hostname}", sudo=True)
    
    return hostname, user_id, os_type, example_num

def update_hosts_file(hostname, lan_config, user_id, os_type, example_num):
    """Update /etc/hosts file with new entries."""
    print("\n=== Updating /etc/hosts ===")
    
    # Create backup of hosts file
    backup_path = f"/etc/hosts.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_command(f"cp /etc/hosts {backup_path}", sudo=True)
    print(f"Created backup of hosts file at {backup_path}")
    
    # Read current hosts file
    with open('/etc/hosts', 'r') as f:
        lines = f.readlines()
    
    # Check if localhost entries exist
    has_localhost_ipv4 = any("127.0.0.1" in line for line in lines)
    has_localhost_ipv6 = any("::1" in line for line in lines)
    
    # Create new lines collection
    new_lines = []
    
    # Add localhost entries if they don't exist
    if not has_localhost_ipv4:
        new_lines.append("127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4\n")
    if not has_localhost_ipv6:
        new_lines.append("::1         localhost localhost.localdomain localhost6 localhost6.localdomain6\n")
    
    # Add existing lines
    for line in lines:
        # Skip if we're going to add this IP later and it's already present
        if lan_config and not lan_config['use_dhcp'] and lan_config['ip_address'] in line:
            continue
        new_lines.append(line)
    
    # Add server/client entries if using static IP
    if lan_config and lan_config['connection_type'].lower() == 'lan' and not lan_config['use_dhcp']:
        server_entry = f"{lan_config['ip_address']} {user_id}-srv.example{example_num}.lab\n"
        client_entry = f"{lan_config['ip_address']} {user_id}-clt.example{example_num}.lab\n"
        
        # Check if entries already exist
        if not any(f"{user_id}-srv.example{example_num}.lab" in line for line in new_lines):
            new_lines.append(server_entry)
        if not any(f"{user_id}-clt.example{example_num}.lab" in line for line in new_lines):
            new_lines.append(client_entry)
    
    # Write updated hosts file
    with open('/etc/hosts', 'w') as f:
        f.writelines(new_lines)
    
    print("/etc/hosts file updated.")

def system_update():
    """Update system packages using yum."""
    print("\n=== System Update ===")
    choice = input("Do you want to update the system packages? (y/n): ").strip().lower()
    
    if choice == 'y':
        print("Updating system packages...")
        result = run_command("yum update -y", sudo=True)
        if result:
            print("System update completed successfully.")
        else:
            print("System update may have encountered issues.")
    else:
        print("Skipping system update.")

def print_summary(lan_config, nat_config, hostname):
    """Print summary of configurations."""
    print("\n" + "=" * 50)
    print("=== Configuration Summary ===")
    print("=" * 50)
    
    print("\nSELinux: Configured to be disabled (requires reboot)")
    print("Firewalld: Disabled")
    
    if lan_config:
        print(f"\nLAN Interface ({lan_config['interface_name']}):")
        if lan_config['use_dhcp']:
            print("  Configuration: DHCP")
        else:
            print(f"  IP Address: {lan_config.get('ip_address', 'N/A')}")
            print(f"  Netmask: {lan_config.get('netmask', 'N/A')}")
            print(f"  Network: {lan_config.get('network', 'N/A')}")
            print(f"  Broadcast: {lan_config.get('broadcast', 'N/A')}")
    else:
        print("\nLAN Interface: Not configured")
    
    if nat_config:
        print(f"\nNAT Interface ({nat_config['interface_name']}):")
        print("  Configuration: DHCP")
    else:
        print("\nNAT Interface: Not configured")
    
    print(f"\nHostname: {hostname}")
    print("\nNetworkManager has been restarted.")
    print("\n" + "=" * 50)
    print("Configuration complete! You may need to reboot for all changes to take effect.")
    print("=" * 50)

def main():
    """Main function to orchestrate the configuration."""
    print("Linux Server/Client Configuration Script")
    print("=" * 50)
    
    # Check prerequisites
    check_root()
    check_distro()
    
    # Security configurations
    disable_selinux()
    manage_firewall()
    
    # Network configurations
    lan_config, nat_config = configure_network_interfaces()
    
    if not lan_config:
        print("LAN configuration is required to continue.")
        sys.exit(1)
    
    # Hostname configuration
    hostname, user_id, os_type, example_num = set_hostname(lan_config)
    
    # Update hosts file
    update_hosts_file(hostname, lan_config, user_id, os_type, example_num)
    
    # System update
    system_update()
    
    # Restart NetworkManager
    restart_network_manager()
    
    # Print summary
    print_summary(lan_config, nat_config, hostname)

if __name__ == "__main__":
    main()
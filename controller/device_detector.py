# controller/device_detector.py
import nmap
import psutil
import socket
import ipaddress
import re
from controller.redis_client import RedisManager

class DeviceDetector:
    @staticmethod
    def check_connectivity(ip_address):
        """Checks connectivity to a specific IP."""
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip_address, arguments='-n -sn -T4 --max-retries 3 --host-timeout 5s')
            return "Online" if ip_address in nm.all_hosts() and nm[ip_address].state() == 'up' else "Offline"
        except Exception as e:
            print(f"Connectivity check error: {e}")
            return "Unknown"

    @staticmethod
    def get_network_interfaces():
        """Returns all active network interfaces with IP addresses."""
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces[interface] = {
                        'ip': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
        return interfaces

    @staticmethod
    def calculate_network_range(ip_address):
        """Calculates the network range based on local IP and subnet mask."""
        interfaces = DeviceDetector.get_network_interfaces()
        for interface, info in interfaces.items():
            if info['ip'] == ip_address:
                try:
                    network = ipaddress.IPv4Network(f"{info['ip']}/{info['netmask']}", strict=False)
                    return str(network)
                except Exception as e:
                    print(f"Error calculating network range: {e}")
                    return None
        return None

    @staticmethod
    def get_device_ip_address():
        """Gets the most likely external IP address of the device."""
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                if interface == 'eth0' or interface.startswith('en') or interface.startswith('wlan0'):
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            return addr.address, interface
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return addr.address, interface
        except Exception as e:
            print(f"Error getting IP address: {e}")
        
        return "127.0.0.1", "localhost"

    @staticmethod
    def detect_device_type(os_info, mac, hostname, open_ports):
        """Enhanced device type detection with better recognition"""
        device_type = "Unknown"
        os_info_str = str(os_info).lower()
        mac_str = str(mac).lower()
        
        # Router detection
        if ('router' in os_info_str or 'mikrotik' in os_info_str or
            any(x in mac_str for x in ['00:1b:17', '00:1d:0f', '00:24:01'])):
            return "Router"
            
        # Windows detection
        if ('windows' in os_info_str or 
            any(x in mac_str for x in ['00:50:f2', '00:03:ff', '00:15:5d']) or
            any(port in ['3389', '445', '139', '135'] for port in open_ports)):
            return "Windows"
        
        # Android detection
        android_mac_prefixes = {
            '38:8b:59', '00:1a:11', '00:26:bb', '88:32:9b', '90:fd:61',
            'a4:5e:60', 'ac:37:43', 'cc:46:d6', 'f8:a9:d0', '00:aa:01'
        }
        if ('android' in os_info_str or
            any(mac_str.startswith(prefix) for prefix in android_mac_prefixes) or
            any(port in ['5555', '5353', '5228'] for port in open_ports)):
            return "Android"
        
        # Linux devices
        if 'linux' in os_info_str:
            if any(p in os_info_str for p in ['server', 'ubuntu', 'debian']):
                return "Linux"
            return "Linux"
            
        return device_type

    @staticmethod
    def scan_network(local_ip, stop_flag=None):
        """Fast network scanning optimized for refresh operations"""
        network_range = DeviceDetector.calculate_network_range(local_ip)
        if not network_range:
            print("Could not determine network range")
            return []

        nm = nmap.PortScanner()
        devices = []
        
        try:
            print(f"Starting fast refresh scan for range: {network_range}")
            
            # Perform ARP ping scan first
            nm.scan(hosts=network_range, arguments='-n -sn -PR -T4 --max-retries 1 --host-timeout 1s')
            
            live_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up' and host != local_ip]
            print(f"Found {len(live_hosts)} live hosts")
            
            if not live_hosts:
                return []
            
            # Now perform a more detailed scan on live hosts
            for i, host in enumerate(live_hosts):
                if stop_flag and stop_flag():
                    print("Scan cancelled by user")
                    return devices
                    
                try:
                    print(f"Scanning host {i+1}/{len(live_hosts)}: {host}")
                    
                    host_nm = nmap.PortScanner()
                    # Fast scan with OS detection
                    host_nm.scan(
                        hosts=host,
                        arguments='-O -T4 --max-retries 1 --host-timeout 2s'
                    )
                    
                    if host not in host_nm.all_hosts():
                        continue
                    
                    # Get device information
                    hostname = host_nm[host].hostname() or "Unknown"
                    mac = host_nm[host]['addresses'].get('mac', 'Unknown')
                    os_info = host_nm[host].get('osmatch', [{}])[0].get('name', 'Unknown')
                    
                    # Get open ports
                    open_ports = []
                    for proto in host_nm[host].all_protocols():
                        open_ports.extend(str(p) for p in host_nm[host][proto].keys())
                    
                    # Detect device type
                    device_type = DeviceDetector.detect_device_type(os_info, mac, hostname, open_ports)
                    
                    # Determine NIC type based on device type and name
                    nic_type = "Unknown"
                    if device_type == "Router":
                        nic_type = "Ethernet/Wi-Fi"
                    elif device_type == "Windows":
                        nic_type = "Wi-Fi" if "wireless" in hostname.lower() else "Ethernet"
                    elif device_type == "Android":
                        nic_type = "Wi-Fi"
                    elif device_type == "Linux":
                        nic_type = "Ethernet/Wi-Fi"
                    
                    device_info = {
                        "ip_address": host,
                        "device_name": hostname if hostname != "Unknown" else device_type,
                        "os_type": device_type,
                        "nic_type": nic_type,
                        "device_mac": mac,
                        "connection_status": "Online"
                    }
                    
                    devices.append(device_info)
                    print(f"Found device: {device_info}")
                    
                except Exception as e:
                    print(f"Error scanning host {host}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Network scan failed: {e}")
        
        return devices
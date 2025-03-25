import nmap
import psutil
import socket
import json
import threading
import ipaddress
import time
from settings import Settings
from Config import Config

# Initialize Settings and Config
Settings = Settings()
Config = Config()

def get_redis_client():
    """Returns a Redis client instance."""
    if Config.check_redis_connection():
        return Config.redis_connection
    else:
        Config._connect_redis()
        return Config.redis_connection

def check_connectivity(ip_address):
    """Checks connectivity to a specific IP."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_address, arguments='-n -sn -T4 --max-retries 1 --host-timeout 5s')
        return "Online" if ip_address in nm.all_hosts() and nm[ip_address].state() == 'up' else "Offline"
    except Exception as e:
        print(f"Connectivity check error: {e}")
        return "Unknown"

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

def calculate_network_range(ip_address):
    """Calculates the network range based on local IP and subnet mask."""
    interfaces = get_network_interfaces()
    for interface, info in interfaces.items():
        if info['ip'] == ip_address:
            try:
                network = ipaddress.IPv4Network(f"{info['ip']}/{info['netmask']}", strict=False)
                return str(network)
            except Exception as e:
                print(f"Error calculating network range: {e}")
                return None
    return None

def scan_network(local_ip):
    """Scans the network for connected devices with proper error handling."""
    network_range = calculate_network_range(local_ip)
    if not network_range:
        print("Could not determine network range")
        return []

    nm = nmap.PortScanner()
    devices = []
    
    try:
        print(f"Starting network scan for range: {network_range}")
        
        # First do a fast ping scan to find live hosts
        print("Performing initial ping scan...")
        nm.scan(hosts=network_range, arguments='-n -sn -T4 --max-retries 1 --host-timeout 5s')
        
        live_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up' and host != local_ip]
        print(f"Found {len(live_hosts)} live hosts")
        
        if not live_hosts:
            return []
        
        # Now scan each live host more thoroughly
        for i, host in enumerate(live_hosts):
            try:
                print(f"Scanning host {i+1}/{len(live_hosts)}: {host}")
                
                # Perform detailed scan with OS detection
                host_nm = nmap.PortScanner()
                host_nm.scan(
                    hosts=host,
                    arguments='-O -T4 -p 22,80,443 --max-retries 1 --host-timeout 15s'
                )
                
                if host not in host_nm.all_hosts():
                    continue
                
                # Get basic info
                hostname = host_nm[host].hostname() or "Unknown"
                mac = host_nm[host]['addresses'].get('mac', 'Unknown')
                
                # Get OS info
                os_info = "Unknown"
                if 'osmatch' in host_nm[host] and host_nm[host]['osmatch']:
                    os_info = host_nm[host]['osmatch'][0]['name']
                
                # Determine device type
                device_type = "Unknown"
                if 'Ruckus' in mac:
                    device_type = "Wireless AP"
                elif 'Routerboard' in mac:
                    device_type = "Router"
                elif 'Linux' in os_info:
                    device_type = "Linux Device"
                
                # Check open ports
                open_ports = []
                for proto in host_nm[host].all_protocols():
                    for port in host_nm[host][proto].keys():
                        if host_nm[host][proto][port]['state'] == 'open':
                            open_ports.append(f"{port}/{proto}")
                
                device_info = {
                    "ip_address": host,
                    "device_name": hostname,
                    "os_type": os_info,
                    "connection_type": device_type,
                    "device_mac": mac,
                    "connection_status": "Online",
                    "open_ports": ", ".join(open_ports) if open_ports else "None"
                }
                
                devices.append(device_info)
                print(f"Found device: {device_info}")
                
            except Exception as e:
                print(f"Error scanning host {host}: {e}")
                continue
                
    except Exception as e:
        print(f"Network scan failed: {e}")
    
    return devices

def get_device_ip_address():
    """Gets the most likely external IP address of the device."""
    try:
        # Try to get default route interface first
        default_gw = None
        for interface, addrs in psutil.net_if_addrs().items():
            if interface == 'eth0' or interface.startswith('en') or interface.startswith('wlan'):
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        return addr.address, interface
        # Fallback to any non-local IP
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    return addr.address, interface
    except Exception as e:
        print(f"Error getting IP address: {e}")
    
    return "127.0.0.1", "localhost"

def get_devices_from_redis(redis_client, network_range):
    """Fetches stored device data from Redis."""
    try:
        data = redis_client.get(f"devices:{network_range}")
        if data:
            return json.loads(data)
    except Exception as e:
        print(f"Redis error: {e}")
    return None

def store_devices_in_redis(redis_client, network_range, devices):
    """Stores device data in Redis with timestamp."""
    try:
        data = {
            'timestamp': time.time(),
            'devices': devices
        }
        redis_client.set(f"devices:{network_range}", json.dumps(data), ex=3600)
    except Exception as e:
        print(f"Redis store error: {e}")
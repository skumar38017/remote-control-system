# controller/controller_backend.py
import nmap
import psutil
import socket
import ipaddress
from controller.redis_client import RedisManager
from controller.device_detector import DeviceDetector

# Initialize Redis Manager
redis_manager = RedisManager()

def check_connectivity(ip_address):
    """Checks connectivity to a specific IP."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_address, arguments='-n -sn -T4 --max-retries 2 --host-timeout 15s')
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
    """Wrapper for DeviceDetector.calculate_network_range"""
    return DeviceDetector.calculate_network_range(ip_address)

def scan_network(local_ip, stop_flag=None):
    """Wrapper for DeviceDetector.scan_network"""
    return DeviceDetector.scan_network(local_ip, stop_flag)

def get_device_ip_address():
    """Wrapper for DeviceDetector.get_device_ip_address"""
    return DeviceDetector.get_device_ip_address()
import tkinter as tk
from tkinter import ttk, messagebox
import platform
from datetime import datetime
import uuid
import threading
import time
from controller.redis_client import RedisManager
from controller.controller_backend import (
    get_device_ip_address, 
    scan_network, 
    calculate_network_range,
)

# Initialize Redis Manager
redis_manager = RedisManager()

# Global variables
devices = []
current_page = 0
devices_per_page = 20
scanning_thread = None
stop_scan_flag = False
root = None

def get_device_info():
    """Returns local device information."""
    device_name = platform.node()
    ip_address, connection_type = get_device_ip_address()
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                   for elements in range(0, 2*6, 2)][::-1])
    os_type = platform.system()
    return device_name, ip_address, mac_address, connection_type, os_type

def update_time():
    """Updates the time label every second."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    time_label.config(text=f" {current_time}  ")
    root.after(1000, update_time)

def show_loading_indicator(message="Scanning network, please wait..."):
    """Shows a loading indicator."""
    global loading_label
    loading_label = tk.Label(root, text=message, font=("Arial", 12))
    loading_label.pack(pady=10)
    root.update()

def hide_loading_indicator():
    """Hides the loading indicator."""
    if 'loading_label' in globals() and loading_label.winfo_exists():
        loading_label.destroy()

def update_treeview(devices_list):
    """Updates the TreeView with properly formatted device information"""
    tree.delete(*tree.get_children())
    
    if not devices_list:
        tree.insert('', 'end', values=("No devices found", "", "", "", "", ""))
        return
    
    for device in devices_list:
        ip = device.get('ip_address', 'Unknown')
        name = device.get('device_name', 'Unknown')
        os_type = device.get('os_type', 'Unknown')
        mac = device.get('device_mac', 'Unknown')
        status = device.get('connection_status', 'Unknown')
        device_type = device.get('connection_type', 'Unknown')
        
        # Determine NIC Type
        nic_type = "Unknown"
        if device_type == "Android Device":
            nic_type = "Wi-Fi"
        elif device_type == "Windows PC":
            nic_type = "Ethernet" if 'eth' in str(name).lower() else "Wi-Fi"
        elif device_type in ["Router", "Network Switch"]:
            nic_type = "Wired"
        elif device_type in ["Linux Device", "Server"]:
            nic_type = "Ethernet/Wi-Fi"
        elif device_type == "Printer":
            nic_type = "Network"
        
        # Clean up OS type display
        if 'Windows' in os_type:
            os_type = "Windows"
        elif 'Android' in os_type:
            os_type = "Android"
        elif 'Linux' in os_type:
            os_type = "Linux"
        elif 'Mac' in os_type or 'Darwin' in os_type:
            os_type = "macOS"
        
        # Insert device with formatted values
        tree.insert('', 'end', values=(ip, name, os_type, nic_type, mac, status))
        
def perform_scan(force_refresh=False):
    """Performs the network scan in a thread."""
    global devices, stop_scan_flag
    
    try:
        ip_address, _ = get_device_ip_address()
        network_range = calculate_network_range(ip_address)
        
        if not network_range:
            root.after(0, lambda: messagebox.showerror(
                "Error", 
                "Could not determine network range. Check your network connection."
            ))
            return
        
        # Clear cache if forcing refresh
        if force_refresh:
            redis_manager.clear_cache(network_range)
        
        # Check Redis first (unless forcing refresh)
        if not force_refresh:
            cached_data = redis_manager.get_devices(network_range)
            if cached_data and time.time() - cached_data['timestamp'] < 300:  # 5 minute cache
                devices = cached_data['devices']
                root.after(0, lambda: update_treeview(devices))
                return
        
        # Perform new scan
        show_loading_indicator()
        
        # Pass a lambda that checks the stop flag
        devices = scan_network(ip_address, stop_flag=lambda: stop_scan_flag)
        
        if devices and not stop_scan_flag:  # Only store if not cancelled
            redis_manager.store_devices(network_range, devices)
        
        root.after(0, lambda: update_treeview(devices))
        
    except Exception as scan_error:
        error_message = f"An error occurred during scanning: {str(scan_error)}"
        root.after(0, lambda: messagebox.showerror("Scan Error", error_message))
    finally:
        root.after(0, hide_loading_indicator())

def scan_and_show_devices(force_refresh=False):
    """Starts the scan in a separate thread."""
    global scanning_thread, stop_scan_flag
    
    stop_scan_flag = False
    
    if scanning_thread and scanning_thread.is_alive():
        messagebox.showinfo("Info", "Scan already in progress")
        return
    
    scanning_thread = threading.Thread(
        target=lambda: perform_scan(force_refresh),
        daemon=True
    )
    scanning_thread.start()

def on_show_list_button_click():
    """Handler for show list button."""
    scan_and_show_devices()

def on_refresh_button_click():
    """Handler for refresh button - forces fresh scan"""
    scan_and_show_devices(force_refresh=True)

def on_cancel_button_click():
    """Exits the application."""
    global stop_scan_flag
    stop_scan_flag = True
    if scanning_thread and scanning_thread.is_alive():
        scanning_thread.join(timeout=1)
    root.quit()

def on_cancel_scan_button_click():
    """Cancels the current scan."""
    global stop_scan_flag
    if messagebox.askokcancel("Confirm", "Are you sure you want to cancel the scan?"):
        stop_scan_flag = True
        hide_loading_indicator()
        messagebox.showinfo("Info", "Scan cancelled")

def create_ui():
    """Creates and configures the main UI."""
    global root, tree, time_label
    
    root = tk.Tk()
    root.title("Network Devices Scanner")
    root.geometry("1000x700")
    root.minsize(800, 600)
    
    # Device info frame
    info_frame = tk.Frame(root)
    info_frame.pack(fill=tk.X, padx=5, pady=5)
    
    # Time label
    time_label = tk.Label(info_frame, text="", font=("Arial", 10))
    time_label.pack(side=tk.LEFT)
    
    # Device info label
    device_name, ip_address, mac_address, connection_type, os_type = get_device_info()
    device_info = f"{device_name} | {os_type} | {connection_type} | {ip_address} | {mac_address}"
    device_label = tk.Label(info_frame, text=device_info, font=("Arial", 10))
    device_label.pack(side=tk.RIGHT)
    
    # Treeview for results
    columns = ('IP Address', 'Device Name', 'OS Type', 'NIC Type', 'MAC Address', 'Status')
    tree = ttk.Treeview(root, columns=columns, show='headings', selectmode='browse')
    
    # Configure column headings and widths
    tree.heading('IP Address', text='IP Address')
    tree.heading('Device Name', text='Device Name')
    tree.heading('OS Type', text='OS Type')
    tree.heading('NIC Type', text='NIC Type')
    tree.heading('MAC Address', text='MAC Address')
    tree.heading('Status', text='Status')
    
    tree.column('IP Address', width=120, anchor=tk.CENTER)
    tree.column('Device Name', width=120, anchor=tk.CENTER)
    tree.column('OS Type', width=100, anchor=tk.CENTER)
    tree.column('NIC Type', width=120, anchor=tk.CENTER)
    tree.column('MAC Address', width=150, anchor=tk.CENTER)
    tree.column('Status', width=80, anchor=tk.CENTER)
    
    tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Add scrollbar
    scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Button frame
    button_frame = tk.Frame(root)
    button_frame.pack(fill=tk.X, padx=5, pady=5)
    
    # Buttons
    show_list_btn = tk.Button(
        button_frame, 
        text="Show List", 
        command=on_show_list_button_click,
        width=15
    )
    show_list_btn.pack(side=tk.LEFT, padx=5)
    
    refresh_btn = tk.Button(
        button_frame, 
        text="Refresh", 
        command=on_refresh_button_click,
        width=15
    )
    refresh_btn.pack(side=tk.LEFT, padx=5)
    
    cancel_scan_btn = tk.Button(
        button_frame, 
        text="Cancel Scan", 
        command=on_cancel_scan_button_click,
        width=15
    )
    cancel_scan_btn.pack(side=tk.RIGHT, padx=5)
    
    cancel_btn = tk.Button(
        button_frame, 
        text="Exit", 
        command=on_cancel_button_click,
        width=15
    )
    cancel_btn.pack(side=tk.RIGHT, padx=5)
    
    # Status bar
    status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_bar.pack(fill=tk.X, padx=5, pady=5)
    
    update_time()
    return root

if __name__ == "__main__":
    root = create_ui()
    root.mainloop()
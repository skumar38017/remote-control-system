import subprocess
import sys
import time
import platform
import signal
import os
import sys

# Global process references
backend_process = None
ui_process = None

def start_backend():
    # Start the FastAPI backend using uvicorn
    print("Starting FastAPI backend...")
    
    # Determine the system platform
    if platform.system() == "Windows":
        # On Windows, use the 'start' command to run uvicorn
        return subprocess.Popen([sys.executable, "-m", "uvicorn", "controller_backend:app", "--reload"], shell=True)
    else:
        # On Linux/macOS, directly use subprocess.Popen
        return subprocess.Popen([sys.executable, "-m", "uvicorn", "controller_backend:app", "--reload"])

def start_ui():
    # Start the Controller UI script
    print("Starting Controller UI...")
    
    # Ensure that the script path is correct for both platforms
    if platform.system() == "Windows":
        return subprocess.Popen([sys.executable, 'controller_ui.py'], shell=True)
    else:
        return subprocess.Popen([sys.executable, 'controller_ui.py'])

def cleanup(signal, frame):
    # Properly terminate backend and UI when closing or pressing Ctrl+C
    print("Shutting down processes...")
    if backend_process:
        backend_process.terminate()
        backend_process.wait()
        print("Backend terminated.")
    if ui_process:
        ui_process.terminate()
        ui_process.wait()
        print("UI terminated.")
    sys.exit(0)  # Exit the program

def main():
    global backend_process, ui_process

    # Set up signal handling to catch Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, cleanup)

    # Start all components (Backend, UI) for the controller
    backend_process = start_backend()
    time.sleep(2)  # Wait for backend to start (you can adjust this)
    ui_process = start_ui()

    # Wait for both processes to finish
    ui_process.wait()
    backend_process.wait()

if __name__ == "__main__":
    main()

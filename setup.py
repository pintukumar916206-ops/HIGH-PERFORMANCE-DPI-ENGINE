import os
import sys
import subprocess
import shutil

def run_cmd(cmd):
    print(f"Running: {' '.join(cmd)}")
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError:
        return False

def setup():
    print("=== Network Traffic Analysis Engine Setup ===")
    
    # 1. Check Python requirements
    print("\n[1/3] Installing Python dependencies...")
    if not run_cmd([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]):
        print("Error: Failed to install Python requirements.")
        
    # 2. Setup environment
    print("\n[2/3] Setting up environment...")
    if not os.path.exists(".env"):
        print("Creating .env from template (or defaults)...")
        with open(".env", "w") as f:
            f.write("SECRET_KEY=" + os.urandom(24).hex() + "\n")
            f.write("DASHBOARD_USERNAME=admin\n")
            f.write("DASHBOARD_PASSWORD=admin\n")
            f.write("PORT=5000\n")
            f.write("ANALYZER_BIN=mock_engine.exe\n")
    
    # 3. Build C++ Engine (Optional/If possible)
    print("\n[3/3] Attempting to build C++ Engine...")
    cmake_found = shutil.which("cmake")
    if cmake_found:
        if not os.path.exists("build"):
            os.makedirs("build")
        
        os.chdir("build")
        if run_cmd(["cmake", ".."]):
            run_cmd(["cmake", "--build", "."])
        os.chdir("..")
    else:
        print("CMake not found. Skipping engine build. Using mock_engine.exe.")

    print("\nSetup Complete!")
    print("To start the dashboard, run: python scripts/dashboard.py")

if __name__ == "__main__":
    setup()

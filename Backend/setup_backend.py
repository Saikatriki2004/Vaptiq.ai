import sys
import subprocess
import importlib

def install(package):
    print(f"Installing {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"Successfully installed {package}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package}. Error: {e}")

def check_and_install():
    print(f"Current Python Executable: {sys.executable}")
    
    required_packages = [
        "fastapi",
        "uvicorn",
        "pydantic",
        "requests"
    ]
    
    # Special handling for dnspython which imports as 'dns'
    try:
        importlib.import_module("dns")
        print(f"✅ dnspython (dns) is already installed")
    except ImportError:
        print(f"❌ dnspython (dns) not found. Attempting to install...")
        install("dnspython")
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"✅ {package} is already installed")
        except ImportError:
            print(f"❌ {package} not found. Attempting to install...")
            install(package)
            
    print("\n--- Verification ---")
    all_good = True
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"❌ Failed to verify {package}")
            all_good = False
            
    # Verify dns separately
    try:
        importlib.import_module("dns")
    except ImportError:
        print(f"❌ Failed to verify dnspython (dns)")
        all_good = False
            
    if all_good:
        print("\n🎉 All dependencies are installed correctly!")
        print("You can now run the server with:")
        print(f"{sys.executable} -m uvicorn main:app --reload")
    else:
        print("\n⚠️ Some packages failed to install. Please check the errors above.")

if __name__ == "__main__":
    check_and_install()

import sys
import traceback
import uvicorn
import os

# Set up logging to file
log_file = "debug_error.log"

def log(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

try:
    log("Starting debug runner...")
    log(f"CWD: {os.getcwd()}")
    log(f"Python: {sys.executable}")
    
    # Try to import main
    log("Importing main module...")
    import main
    log("Main module imported successfully.")
    
    # Try to start uvicorn
    log("Starting Uvicorn programmatically...")
    uvicorn.run(main.app, host="127.0.0.1", port=8000)
    
except Exception as e:
    log("CRITICAL ERROR CAUGHT:")
    log(traceback.format_exc())
    print(traceback.format_exc())

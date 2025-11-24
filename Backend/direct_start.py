import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

print(f"Working Directory: {os.getcwd()}")
print(f"Python: {sys.executable}")
print("=" * 60)

# Step 1: Install dependencies
print("\n[STEP 1] Installing dependencies...")
try:
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        capture_output=True,
        text=True,
        timeout=120
    )
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    print("✓ Dependencies installation attempted")
except Exception as e:
    print(f"⚠️ Dependency installation error: {e}")
    print("Continuing anyway...")

# Step 2: Import and verify main module
print("\n[STEP 2] Verifying main module...")
try:
    import main
    print("✓ Main module imported successfully")
    print(f"✓ FastAPI app found: {main.app}")
except Exception as e:
    print(f"✗ Failed to import main module:")
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    # input("Press Enter to exit...") # DISABLED FOR CI
    sys.exit(1)

# Step 3: Start uvicorn
print("\n[STEP 3] Starting Uvicorn server...")
print("=" * 60)
print("Backend will be available at:")
print("  - http://localhost:8000")
print("  - http://localhost:8000/docs (API Documentation)")
print("=" * 60)
print("\nPress Ctrl+C to stop the server\n")

try:
    import uvicorn
    # Mock uvicorn run for test
    if os.getenv("TEST_MODE") == "True":
        print("Test Mode: skipping uvicorn.run")
    else:
        uvicorn.run(
            main.app,
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
except KeyboardInterrupt:
    print("\n\nServer stopped by user")
except Exception as e:
    print(f"\n\n✗ Server crashed:")
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    # input("Press Enter to exit...") # DISABLED FOR CI
    sys.exit(1)

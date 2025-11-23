import sys
import os

with open("diagnostic_output.txt", "w") as f:
    f.write(f"Python Executable: {sys.executable}\n")
    f.write(f"Current Working Directory: {os.getcwd()}\n")
    f.write("File writing is working.\n")

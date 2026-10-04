# kv-fisa
finding vulnerabiities
import sys
import subprocess

def install_package(package):
    """Install a package via pip if not already installed."""
    try:
        __import__(package)
    except ImportError:
        print(f"[+] Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def run_vulnerability_scan():
    """Run pip-audit to check for known vulnerabilities."""
    try:
        import pip_audit
    except ImportError:
        install_package("pip-audit")
        import pip_audit

    print("[+] Running vulnerability scan on installed packages...\n")
    try:
        # Run pip-audit as a subprocess to get clean output
        subprocess.run([sys.executable, "-m", "pip_audit"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running pip-audit: {e}")

if __name__ == "__main__":
    run_vulnerability_scan()

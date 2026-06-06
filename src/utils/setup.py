#!/usr/bin/env python3
"""
CyberShield Setup Script
Installs dependencies and prepares the system for Raspberry Pi
"""

import os
import sys
import subprocess
import platform
import shutil


def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║     CyberShield Multi-Layer Threat Detection     ║
    ║                 Setup Wizard                      ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def check_python():
    """Check Python version"""
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 8):
        print(f"❌ Python 3.8+ required. Current: {major}.{minor}")
        sys.exit(1)
    print(f"✓ Python {major}.{minor}")


def check_platform():
    """Check platform"""
    system = platform.system()
    machine = platform.machine()
    print(f"✓ Platform: {system} ({machine})")
    
    if system != "Linux":
        print("⚠ This setup is for Raspberry Pi/Linux")
        print("  For Windows, just run: pip install -r requirements.txt")
        return False
    
    # Check for Raspberry Pi
    try:
        with open('/proc/cpuinfo', 'r') as f:
            if 'Raspberry' in f.read():
                print("✓ Raspberry Pi detected!")
    except:
        pass
    
    return True


def create_dirs():
    """Create required directories"""
    dirs = ['logs', 'captures', 'models/mbert_phishing']
    print("\n📁 Creating directories...")
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"   ✓ {d}")


def install_pip_deps():
    """Install Python packages"""
    print("\n📦 Installing Python dependencies...")
    
    # Upgrade pip first
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                   capture_output=True)
    
    # Install from requirements
    result = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print("✓ Dependencies installed")
    else:
        print("⚠ Some packages may have failed")
        print("  Try manually: pip3 install -r requirements.txt")


def install_system_deps():
    """Install system packages"""
    print("\n🔧 Installing system dependencies...")
    
    packages = ['tcpdump', 'iptables', 'net-tools']
    
    for pkg in packages:
        result = subprocess.run(
            ['dpkg', '-s', pkg],
            capture_output=True
        )
        if result.returncode == 0:
            print(f"   ✓ {pkg} already installed")
        else:
            print(f"   Installing {pkg}...")
            subprocess.run(['sudo', 'apt', 'install', '-y', pkg])


def init_database():
    """Initialize database"""
    print("\n🗄️ Setting up database...")
    try:
        from data_layer.database.db_manager import Database
        db = Database('threats.db')
        print("✓ Database initialized")
        db.close()
    except Exception as e:
        print(f"⚠ Database setup: {e}")


def check_models():
    """Verify model files exist"""
    print("\n🔍 Checking ML models...")
    
    models = {
        'URL Model': 'models/url/rf_url_model.pkl',
        'URL Features': 'models/url/feature_columns.pkl',
        'URL Labels': 'models/url/label_encoder.pkl',
        'App Attack Model': 'models/app_attack/web_attack_rf.pkl',
        'TF-IDF Vectorizer': 'models/app_attack/tfidf_vectorizer.pkl',
        'App Labels': 'models/app_attack/label_encoder.pkl',
        'DPI Pipeline': 'models/dpi/dpi_rf_pipeline.pkl',
    }
    
    all_found = True
    for name, path in models.items():
        if os.path.exists(path):
            size = os.path.getsize(path) / 1024
            print(f"   ✓ {name} ({size:.0f} KB)")
        else:
            print(f"   ❌ {name} - MISSING: {path}")
            all_found = False
    
    # Check email model
    email_dir = 'models/email/final_multilingual_model'
    if os.path.exists(email_dir):
        files = os.listdir(email_dir)
        if 'config.json' in files:
            print(f"   ✓ Email Model ({len(files)} files)")
        else:
            print(f"   ⚠ Email Model incomplete")
            all_found = False
    else:
        print(f"   ❌ Email Model - MISSING: {email_dir}")
        all_found = False
    
    if not all_found:
        print("\n⚠ Some models missing. Copy them from your training environment.")
    
    return all_found


def enable_ip_forwarding():
    """Enable IP forwarding for gateway mode"""
    print("\n🌐 Enabling IP forwarding...")
    
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        print("✓ IP forwarding enabled (temporary)")
        
        # Make permanent
        subprocess.run(
            ['sudo', 'sed', '-i', 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/', 
             '/etc/sysctl.conf'],
            capture_output=True
        )
        print("✓ IP forwarding enabled (permanent)")
    except Exception as e:
        print(f"⚠ Could not enable IP forwarding: {e}")
        print("  Run: sudo sysctl -w net.ipv4.ip_forward=1")


def create_service():
    """Create systemd service for auto-start"""
    print("\n📋 Creating systemd service...")
    
    service = """[Unit]
Description=CyberShield Threat Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={workdir}
ExecStart={python} {workdir}/run_live.py -i eth0
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    workdir = os.path.abspath('.')
    python = sys.executable
    
    service_content = service.format(workdir=workdir, python=python)
    
    service_path = '/etc/systemd/system/cybershield.service'
    
    try:
        with open('/tmp/cybershield.service', 'w') as f:
            f.write(service_content)
        
        subprocess.run(['sudo', 'cp', '/tmp/cybershield.service', service_path])
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
        
        print("✓ Service created")
        print("\n  To enable auto-start on boot:")
        print("  sudo systemctl enable cybershield")
        print("  sudo systemctl start cybershield")
        print("\n  To check status:")
        print("  sudo systemctl status cybershield")
    except Exception as e:
        print(f"⚠ Could not create service: {e}")
        print("  You can still run manually: sudo python3 run_live.py")


def print_done():
    """Print completion message"""
    print("\n" + "=" * 50)
    print(" ✅ SETUP COMPLETE!")
    print("=" * 50)
    print("\n📝 To run the system:")
    print("\n  1. Test mode (simulated traffic):")
    print("     sudo python3 run.py")
    print("\n  2. Live mode (real packet capture):")
    print("     sudo python3 run_live.py -i eth0")
    print("\n  3. Dashboard:")
    print("     http://<raspberry-pi-ip>:5000")
    print("\n  4. Firewall/Transparent proxy:")
    print("     sudo bash setup_firewall.sh")
    print("=" * 50)


def main():
    print_banner()
    
    check_python()
    
    if not check_platform():
        print("\nSetup complete for Windows testing.")
        print("Run: pip install -r requirements.txt")
        sys.exit(0)
    
    create_dirs()
    install_system_deps()
    install_pip_deps()
    init_database()
    check_models()
    enable_ip_forwarding()
    create_service()
    print_done()


if __name__ == '__main__':
    main()
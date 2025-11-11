# Wire Interpreter - Cyberpunk NMAP Network Scanner

A futuristic, cyberpunk-styled web interface for NMAP network scanning with real-time visualization and device identification.

## 🚀 Features

### Cyberpunk HUD Interface
- **Futuristic Design**: Glass morphism panels with neon cyan accents
- **Animated Background**: Moving grid pattern for immersive experience
- **Holographic Typography**: Orbitron and Fira Code fonts
- **Gaming Panel Aesthetics**: Professional dashboard design

### Advanced Network Scanning
- **Real-time Progress**: Live scan status updates with detailed messages
- **Device Intelligence**: OID-based device identification using NMAP data
- **Thorough Mode**: Enhanced scanning for identified devices (-A -T4)
- **Visual Distinction**: Grey styling for unidentified devices

### Interactive Network Graph
- **Hierarchical Layout**: Professional network topology visualization
- **Device Classification**: Routers, servers, computers, mobile, IoT devices
- **Zoom & Pan**: Full navigation controls
- **Click Details**: Device information on click

## 🛠️ Installation

### Prerequisites (All Platforms)
- **Python 3.8+**: Download from [python.org](https://python.org)
- **NMAP**: Network scanning tool (see platform-specific instructions below)
- **Modern Web Browser**: Chrome, Firefox, Safari, or Edge
- **Git**: For cloning the repository

### 📥 Download & Setup

```bash
# Clone the repository
git clone https://github.com/k4lli/nmap-frontend.git
cd nmap-frontend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 🐧 Linux Installation

#### Ubuntu/Debian
```bash
# Install NMAP
sudo apt update
sudo apt install nmap

# Optional: Enable MAC address capture (requires root)
sudo apt install python3-nmap

# For MAC address and OS detection (optional but recommended):
# Add to /etc/sudoers (replace 'username' with your username):
# username ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

#### CentOS/RHEL/Fedora
```bash
# Install NMAP
sudo yum install nmap          # CentOS/RHEL
sudo dnf install nmap          # Fedora

# Optional: Enable MAC address capture
sudo yum install python3-nmap  # CentOS/RHEL
sudo dnf install python3-nmap  # Fedora
```

#### Arch Linux
```bash
# Install NMAP
sudo pacman -S nmap

# Optional: Enable MAC address capture
sudo pacman -S python-nmap
```

### 🍎 macOS Installation

#### Using Homebrew (Recommended)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install NMAP
brew install nmap

# Optional: Enable MAC address capture (requires sudo)
# Add to /etc/sudoers (replace 'username' with your username):
# username ALL=(ALL) NOPASSWD: /usr/local/bin/nmap
```

#### Using MacPorts
```bash
# Install MacPorts if not already installed
# Then install NMAP
sudo port install nmap
```

### 🪟 Windows Installation

#### Using Chocolatey (Recommended)
```powershell
# Install Chocolatey if not already installed
# Then install NMAP
choco install nmap

# Install Python if not already installed
choco install python

# Install Git if not already installed
choco install git
```

#### Manual Installation
1. **Download NMAP**: Get the Windows installer from [nmap.org/download.html](https://nmap.org/download.html)
2. **Install Python**: Download from [python.org](https://python.org)
3. **Install Git**: Download from [git-scm.com](https://git-scm.com)

#### Windows-Specific Notes
- **Firewall**: Windows Firewall may block NMAP scans
- **Privileges**: Run Command Prompt as Administrator for full functionality
- **MAC Addresses**: May require Administrator privileges for local network scanning

### 🚀 Running the Application

#### All Platforms
```bash
# Activate virtual environment (if not already activated)
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# Run the application
python app.py
```

#### Access the Application
- Open your web browser
- Navigate to: `http://localhost:5000`
- The cyberpunk interface will load automatically

### 🔧 Advanced Configuration

#### MAC Address & OS Detection (Recommended)
For full functionality including MAC addresses and OS detection:

**Linux/macOS:**
```bash
# Edit sudoers file
sudo visudo

# Add this line (replace 'username' with your actual username):
username ALL=(ALL) NOPASSWD: /usr/bin/nmap
# On macOS with Homebrew:
/usr/local/bin/nmap
```

**Windows:**
- Run the application as Administrator
- Some MAC address features may be limited due to Windows security restrictions

## 🐳 Docker Deployment

### Prerequisites
- Docker installed on your system
- Docker Compose (optional, for advanced setups)

### Quick Start with Docker
```bash
# Clone the repository
git clone https://github.com/k4lli/nmap-frontend.git
cd nmap-frontend

# Build the Docker image
docker build -t wire-interpreter .

# Run the container
docker run -p 5000:5000 wire-interpreter
```

### Advanced Docker Usage

#### Custom Build
```bash
# Build with specific Python version
docker build --build-arg PYTHON_VERSION=3.11 -t wire-interpreter .

# Run with custom port
docker run -p 8080:5000 wire-interpreter

# Run in background
docker run -d -p 5000:5000 --name wire-scanner wire-interpreter
```

#### Docker Compose (Recommended for Production)
```yaml
# Create docker-compose.yml
version: '3.8'
services:
  wire-interpreter:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
```

```bash
# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

### Docker Security Considerations
- **Network Scanning**: Container has limited network access
- **Privileged Mode**: May need `--privileged` flag for full NMAP functionality
- **Volume Mounting**: Consider mounting volumes for persistent data
- **Resource Limits**: Set appropriate CPU and memory limits

### Docker Troubleshooting
```bash
# Check container logs
docker logs wire-interpreter

# Access container shell
docker exec -it wire-interpreter /bin/bash

# Rebuild without cache
docker build --no-cache -t wire-interpreter .
```

## 🔧 Configuration & Troubleshooting

### Common Issues

#### NMAP Not Found
```bash
# Check if NMAP is installed
nmap --version

# Linux/macOS
which nmap

# Windows
where nmap
```

#### Permission Errors
```bash
# Linux/macOS: Check sudo access
sudo nmap --version

# Windows: Run as Administrator
# Right-click Command Prompt → Run as Administrator
```

#### Port Already in Use
```bash
# Kill process using port 5000
# Linux/macOS:
lsof -ti:5000 | xargs kill -9

# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

#### Python Virtual Environment Issues
```bash
# Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

## 📋 Configuration

### Scan Options
- **Ping Scan (-sn)**: Fast host discovery
- **SYN Scan (-sS)**: Stealth scanning
- **Version Scan (-sV)**: Service detection
- **OS Detection (-O)**: Operating system fingerprinting
- **Aggressive Scan (-A)**: Comprehensive scanning
- **Port Scans**: Various port scanning options

### Timing Templates
- **Paranoid (-T0)**: Very slow, IDS evasion
- **Sneaky (-T1)**: Slow, IDS evasion
- **Polite (-T2)**: Slow, bandwidth conscious
- **Normal (-T3)**: Default timing
- **Aggressive (-T4)**: Fast scanning
- **Insane (-T5)**: Very fast, less reliable

## 🔒 Security Notes

- This tool requires NMAP to be installed and properly configured
- Network scanning may require appropriate permissions
- Use responsibly and only on networks you own or have permission to scan
- The application runs locally on your machine for security

## 🏗️ Architecture

### Backend (Flask)
- **API Endpoints**: RESTful API for scanning operations
- **Real-time Updates**: WebSocket-like polling for scan progress
- **Device Intelligence**: NMAP data parsing and device classification

### Frontend (Vanilla JS)
- **Cyberpunk UI**: Custom CSS with glass morphism effects
- **Network Visualization**: Vis.js powered graph rendering
- **Real-time Updates**: AJAX polling for live status

### Key Files
- `app.py`: Flask backend server
- `templates/index.html`: Main UI template
- `static/css/style.css`: Cyberpunk styling
- `static/js/app.js`: Frontend logic
- `requirements.txt`: Python dependencies
- `Dockerfile`: Container configuration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source. Please use responsibly and ethically.

## ⚠️ Disclaimer

This tool is for educational and network administration purposes. Always ensure you have proper authorization before scanning networks. The developers are not responsible for misuse of this software.

---

**Built with ❤️ for network professionals and cyberpunk enthusiasts**

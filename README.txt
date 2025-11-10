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

### Prerequisites
- Python 3.8+
- NMAP installed on system
- Modern web browser

### Setup
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/nmap-frontend.git
cd nmap-frontend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Visit `http://localhost:5000` in your browser.

## 🐳 Docker Deployment

```bash
# Build the container
docker build -t wire-interpreter .

# Run the container
docker run -p 5000:5000 wire-interpreter
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

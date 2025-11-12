from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import nmap
import socket
import json
import subprocess
import threading
import time
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

# Load API key (optional)
MACLOOKUP_API_KEY = None
try:
    with open('my.maclookup.app.key', 'r') as f:
        MACLOOKUP_API_KEY = f.read().strip()
except FileNotFoundError:
    print("Warning: my.maclookup.app.key not found. External MAC lookup will be limited.")
    MACLOOKUP_API_KEY = None

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nmap_frontend.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    logo_url = db.Column(db.String(500))

class OidCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_prefix = db.Column(db.String(20), unique=True, nullable=False)
    vendor_name = db.Column(db.String(100), nullable=False)

# Vendor to domain mapping for logo fetching
vendor_domains = {
    "ASUSTek Computer": "asus.com",
    "Apple": "apple.com",
    "Google": "google.com",
    "TP-Link": "tp-link.com",
    "Netgear": "netgear.com",
    "D-Link": "dlink.com",
    "Linksys": "linksys.com",
    "Microsoft": "microsoft.com",
    "Samsung": "samsung.com",
    "Huawei": "huawei.com",
    "Xiaomi": "xiaomi.com",
    "OnePlus": "oneplus.com",
    "Sony": "sony.com",
    "LG": "lg.com",
    "Panasonic": "panasonic.com",
    "Philips": "philips.com",
    "Roku": "roku.com",
    "Amazon": "amazon.com",
    "Nest": "nest.com",
    "Chromecast": "google.com",
}

def get_vendor_logo(vendor_name):
    if vendor_name in vendor_domains:
        domain = vendor_domains[vendor_name]
    else:
        # Auto-generate domain from first word
        first_word = vendor_name.split()[0].lower()
        domain = f"{first_word}.com"
    return f"https://logo.clearbit.com/{domain}"

def lookup_mac_vendor(mac):
    """Fallback MAC vendor lookup by scraping maclookup.app"""
    try:
        url = f"https://maclookup.app/search/result?mac={mac}"
        print(f"DEBUG: Scraping URL: {url}")
        response = requests.get(url, timeout=5)
        print(f"DEBUG: Response status: {response.status_code}")
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Find the vendor name
            # Looking for text after "Vendor name:"
            text = soup.get_text()
            print(f"DEBUG: Page text snippet: {text[:500]}")
            if "Vendor name:" in text:
                vendor_start = text.find("Vendor name:") + len("Vendor name:")
                vendor_end = text.find("\n", vendor_start)
                vendor = text[vendor_start:vendor_end].strip()
                print(f"DEBUG: Extracted vendor: '{vendor}'")
                if vendor and vendor != "Unknown":
                    return vendor
        else:
            print(f"DEBUG: HTTP error: {response.status_code}")
    except Exception as e:
        print(f"Error looking up MAC {mac}: {e}")
    return 'Unknown'

# Global variables for scan status
scan_output = []
scan_in_progress = False
last_scan_devices = []

def get_local_network():
    """Get local network IP and subnet"""
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Calculate subnet (assuming /24)
        ip_parts = local_ip.split('.')
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return subnet
    except:
        return "192.168.1.0/24"  # fallback

def get_device_info_from_oid(host):
    """Extract device information from NMAP OID data"""
    device_info = {
        'vendor': 'Unknown',
        'device_type': 'Unknown',
        'os_info': 'Unknown',
        'identified': False,
        'logo_url': None
    }

    with app.app_context():
        try:
            mac = 'Unknown'
            # Get MAC address
            if 'addresses' in host and 'mac' in host['addresses']:
                mac = host['addresses']['mac']
                print(f"DEBUG: Retrieved MAC: {mac}")
            else:
                print("DEBUG: No MAC address found in host data")

            # Check OID cache first
            if mac != 'Unknown':
                prefix = mac[:8]  # e.g., 3C:7C:3F
                cached = OidCache.query.filter_by(mac_prefix=prefix).first()
                if cached:
                    device_info['vendor'] = cached.vendor_name
                    device_info['identified'] = True
                    print(f"DEBUG: Found vendor in cache: {cached.vendor_name}")
                else:
                    print(f"DEBUG: MAC prefix {prefix} not in cache")
                    # Get vendor from NMAP
                    if 'vendor' in host:
                        vendor = host['vendor'].get(mac, 'Unknown')
                        print(f"DEBUG: NMAP vendor data: {vendor}")
                        if vendor != 'Unknown':
                            device_info['vendor'] = vendor
                            device_info['identified'] = True
                            # Cache it
                            try:
                                db.session.add(OidCache(mac_prefix=prefix, vendor_name=vendor))
                                db.session.commit()
                                print(f"DEBUG: Cached NMAP vendor: {vendor}")
                            except Exception as e:
                                db.session.rollback()
                                print(f"Error caching OID: {e}")

                    # Fallback to external API if still unknown
                    if device_info['vendor'] == 'Unknown':
                        print(f"DEBUG: Calling external API for MAC: {mac}")
                        vendor = lookup_mac_vendor(mac)
                        print(f"DEBUG: External API returned: {vendor}")
                        if vendor != 'Unknown':
                            device_info['vendor'] = vendor
                            device_info['identified'] = True
                            # Cache it
                            try:
                                db.session.add(OidCache(mac_prefix=prefix, vendor_name=vendor))
                                db.session.commit()
                                print(f"DEBUG: Cached external vendor: {vendor}")
                            except Exception as e:
                                db.session.rollback()
                                print(f"Error caching external OID: {e}")

            # Get logo for vendor
            if device_info['vendor'] != 'Unknown':
                vendor_obj = Vendor.query.filter_by(name=device_info['vendor']).first()
                if vendor_obj and vendor_obj.logo_url:
                    device_info['logo_url'] = vendor_obj.logo_url
                else:
                    logo = get_vendor_logo(device_info['vendor'])
                    if logo:
                        try:
                            if not vendor_obj:
                                db.session.add(Vendor(name=device_info['vendor'], logo_url=logo))
                            else:
                                vendor_obj.logo_url = logo
                            db.session.commit()
                            device_info['logo_url'] = logo
                        except Exception as e:
                            db.session.rollback()
                            print(f"Error caching logo: {e}")

            # Get OS information if available
            if 'osmatch' in host and host['osmatch']:
                best_match = host['osmatch'][0]  # Best OS match
                device_info['os_info'] = best_match.get('name', 'Unknown')
                device_info['identified'] = True

            # Determine device type from OS info and other data
            os_name = device_info['os_info'].lower()
            hostname = host.hostname() if callable(host.hostname) else (host.get('hostname', '') if isinstance(host, dict) else '')

            if 'linux' in os_name:
                if 'android' in os_name or 'iphone' in hostname.lower():
                    device_info['device_type'] = 'mobile'
                elif 'server' in os_name or any(port.get('name', '') in ['ssh', 'http', 'https'] for port in host.get('tcp', {}).values() if port.get('state') == 'open'):
                    device_info['device_type'] = 'server'
                else:
                    device_info['device_type'] = 'computer'
            elif 'windows' in os_name:
                device_info['device_type'] = 'computer'
            elif 'mac os' in os_name or 'ios' in os_name:
                device_info['device_type'] = 'mobile'
            elif 'router' in os_name or 'switch' in os_name:
                device_info['device_type'] = 'router'
            elif 'roku' in hostname.lower() or 'tivo' in hostname.lower():
                device_info['device_type'] = 'iot'
            else:
                device_info['device_type'] = 'computer'

        except Exception as e:
            print(f"Error extracting device info: {e}")

    return device_info

def run_nmap_scan(target, options, thorough=False):
    """Run NMAP scan in background with progress updates"""
    global scan_output, scan_in_progress, last_scan_devices
    scan_in_progress = True
    scan_output = []

    try:
        scan_output.append(f"Starting NMAP scan on {target} with options: {options}")
        time.sleep(0.5)  # Allow status update

        # Calculate approximate number of hosts to scan for progress
        if '/' in target:
            # CIDR notation like 192.168.1.0/24
            import ipaddress
            try:
                network = ipaddress.ip_network(target, strict=False)
                total_hosts = network.num_addresses - 2  # Exclude network and broadcast
                scan_output.append(f"Scanning approximately {total_hosts} hosts...")
                time.sleep(0.5)
            except:
                scan_output.append("Scanning network...")
                time.sleep(0.5)
        else:
            scan_output.append("Scanning target...")
            time.sleep(0.5)

        # Run the actual NMAP scan
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=options)

        devices = []
        identified_devices = []

        scan_output.append("Processing scan results...")
        time.sleep(0.5)

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                scan_output.append(f"Processing host: {host}")
                time.sleep(0.2)  # Allow status update

                # Get device info from NMAP OID data
                device_info = get_device_info_from_oid(nm[host])

                device = {
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else 'Unknown',
                    'state': nm[host].state(),
                    'mac': nm[host]['addresses'].get('mac', 'Unknown'),
                    'vendor': device_info['vendor'],
                    'device_type': device_info['device_type'],
                    'os_info': device_info['os_info'],
                    'identified': device_info['identified'],
                    'logo_url': device_info.get('logo_url'),
                    'ports': []
                }

                # Get open ports
                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        if nm[host]['tcp'][port]['state'] == 'open':
                            device['ports'].append({
                                'port': port,
                                'service': nm[host]['tcp'][port]['name'],
                                'state': nm[host]['tcp'][port]['state']
                            })

                devices.append(device)

                if device_info['identified']:
                    identified_devices.append(host)
                    scan_output.append(f"✓ Identified: {host} ({device_info['vendor']}) - {device_info['device_type']}")
                else:
                    scan_output.append(f"○ Found: {host} (unidentified)")

                time.sleep(0.3)  # Allow status update

        scan_output.append(f"Discovery complete: {len(devices)} devices found")

        # If thorough scanning is enabled and we have identified devices, run detailed scans
        if thorough and identified_devices:
            scan_output.append(f"Running thorough scans on {len(identified_devices)} identified devices...")
            time.sleep(0.5)

            for i, ip in enumerate(identified_devices, 1):
                try:
                    scan_output.append(f"[{i}/{len(identified_devices)}] Detailed scan: {ip}")
                    time.sleep(0.3)

                    # Run a more comprehensive scan on identified devices
                    detailed_nm = nmap.PortScanner()
                    detailed_nm.scan(hosts=ip, arguments='-A -T4')  # Aggressive scan with OS detection

                    # Update device with detailed information
                    for device in devices:
                        if device['ip'] == ip and detailed_nm[ip].state() == 'up':
                            device_info = get_device_info_from_oid(detailed_nm[ip])
                            device['os_info'] = device_info['os_info']
                            device['identified'] = device_info['identified']

                            # Update ports with detailed info
                            device['ports'] = []
                            if 'tcp' in detailed_nm[ip]:
                                for port in detailed_nm[ip]['tcp']:
                                    if detailed_nm[ip]['tcp'][port]['state'] == 'open':
                                        device['ports'].append({
                                            'port': port,
                                            'service': detailed_nm[ip]['tcp'][port]['name'],
                                            'state': detailed_nm[ip]['tcp'][port]['state']
                                        })

                            scan_output.append(f"✓ Enhanced: {ip} with detailed information")
                            break

                    time.sleep(0.5)  # Allow status update

                except Exception as e:
                    scan_output.append(f"✗ Failed detailed scan for {ip}: {str(e)}")

        scan_output.append("🎉 Scan completed successfully!")
        last_scan_devices = devices  # Store the results
        return devices

    except Exception as e:
        scan_output.append(f"❌ Scan failed: {str(e)}")
        last_scan_devices = []
        return []
    finally:
        scan_in_progress = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/network')
def get_network():
    return jsonify({'network': get_local_network()})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global scan_in_progress, scan_output, last_scan_devices

    # Reset scan state if a scan is in progress
    if scan_in_progress:
        scan_output.append("⚠️ Previous scan cancelled - starting new scan")
        scan_in_progress = False
        last_scan_devices = []
        time.sleep(0.5)  # Brief pause to allow cleanup

    data = request.get_json()
    target = data.get('target', get_local_network())
    options = data.get('options', '-sn')
    thorough = data.get('thorough', False)

    # Start scan in background thread
    thread = threading.Thread(target=run_nmap_scan, args=(target, options, thorough))
    thread.daemon = True
    thread.start()

    return jsonify({'message': 'Scan started', 'target': target, 'options': options, 'thorough': thorough})

@app.route('/api/scan/status')
def scan_status():
    return jsonify({
        'in_progress': scan_in_progress,
        'output': scan_output[-10:]  # Last 10 lines
    })

@app.route('/api/devices')
def get_devices():
    global last_scan_devices
    return jsonify({'devices': last_scan_devices})

@app.route('/api/scan/log')
def get_full_log():
    global scan_output
    return jsonify({'log': scan_output})

@app.route('/api/save_scan')
def save_scan():
    global last_scan_devices
    if not last_scan_devices:
        return jsonify({'error': 'No scan data available'}), 400

    data = {
        'timestamp': datetime.now().isoformat(),
        'devices': last_scan_devices
    }
    return jsonify(data)

@app.route('/api/load_scan', methods=['POST'])
def load_scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        data = json.load(file)
        devices = data.get('devices', [])
        return jsonify({'devices': devices})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/status')
def get_app_status():
    """Check application status including API key availability"""
    api_key_exists = os.path.exists('my.maclookup.app.key')
    return jsonify({
        'api_key_exists': api_key_exists,
        'database_ready': True  # We'll assume DB is ready if app starts
    })

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

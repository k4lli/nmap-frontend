from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import nmap
import socket
import json
import subprocess
import threading
import time
import os

app = Flask(__name__)
CORS(app)

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
        'identified': False
    }

    try:
        # Get MAC address vendor from NMAP
        if 'addresses' in host and 'mac' in host['addresses']:
            mac = host['addresses']['mac']
            # NMAP provides vendor information directly
            if 'vendor' in host:
                device_info['vendor'] = host['vendor'].get(mac, 'Unknown')
                device_info['identified'] = True

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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

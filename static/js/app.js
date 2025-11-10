// Wire Interpreter - NMAP Network Scanner Frontend
class WireInterpreter {
    constructor() {
        this.network = null;
        this.devices = [];
        this.scanInterval = null;
        this.lastLogContent = '';
        this.lastScanStatus = null;
        this.graphInitialized = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadNetworkInfo();
        this.initializeGraph();
        this.startStatusUpdates();
    }

    bindEvents() {
        const scanButton = document.getElementById('scan-button');
        const targetInput = document.getElementById('target');
        const scanTypeSelect = document.getElementById('scan-type');
        const timingSelect = document.getElementById('timing');
        const additionalOptions = document.getElementById('additional-options');
        const thoroughScanCheckbox = document.getElementById('thorough-scan');

        scanButton.addEventListener('click', () => this.startScan());

        // Auto-populate target on load
        this.loadNetworkInfo().then(network => {
            if (network && targetInput.value === '') {
                targetInput.value = network;
            }
        });
    }

    async loadNetworkInfo() {
        try {
            const response = await fetch('/api/network');
            const data = await response.json();
            return data.network;
        } catch (error) {
            console.error('Failed to load network info:', error);
            return null;
        }
    }

    initializeGraph() {
        const container = document.getElementById('network-graph');

        const options = {
            nodes: {
                shape: 'box',
                size: 30,
                font: {
                    color: '#00ffff',
                    size: 12,
                    face: 'Orbitron, Courier New',
                    align: 'center'
                },
                borderWidth: 2,
                borderColor: '#00ffff',
                color: {
                    background: '#0a0a0a',
                    border: '#00ffff',
                    highlight: {
                        background: '#1a1a1a',
                        border: '#00aaaa'
                    }
                },
                margin: 10,
                widthConstraint: {
                    minimum: 80,
                    maximum: 150
                },
                shadow: {
                    enabled: true,
                    color: 'rgba(0, 255, 255, 0.3)',
                    size: 5,
                    x: 0,
                    y: 0
                }
            },
            edges: {
                color: '#00ffff',
                width: 3,
                arrows: {
                    to: { enabled: false }
                },
                smooth: {
                    type: 'cubicBezier',
                    forceDirection: 'vertical',
                    roundness: 0.4
                },
                shadow: {
                    enabled: true,
                    color: 'rgba(0, 255, 255, 0.2)',
                    size: 3,
                    x: 0,
                    y: 0
                }
            },
            layout: {
                hierarchical: {
                    direction: 'UD', // Up-Down layout
                    sortMethod: 'directed',
                    levelSeparation: 150,
                    nodeSpacing: 100,
                    treeSpacing: 200,
                    blockShifting: true,
                    edgeMinimization: true,
                    parentCentralization: true
                }
            },
            physics: {
                enabled: false // Disable physics for hierarchical layout
            },
            interaction: {
                hover: true,
                tooltipDelay: 300,
                dragNodes: false, // Disable dragging for cleaner layout
                zoomView: true,
                dragView: true
            },
            manipulation: {
                enabled: false
            }
        };

        this.network = new vis.Network(container, { nodes: [], edges: [] }, options);
        this.network.on('hoverNode', (params) => this.onNodeHover(params));
        this.network.on('blurNode', () => this.onNodeBlur());
        this.network.on('click', (params) => this.onNodeClick(params));
    }

    onNodeHover(params) {
        const nodeId = params.node;
        const device = this.devices.find(d => d.id === nodeId);
        if (device) {
            this.showDeviceTooltip(device);
        }
    }

    onNodeBlur() {
        // Hide tooltip if needed
    }

    onNodeClick(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const device = this.devices.find(d => d.ip === nodeId);
            if (device) {
                this.showDeviceDetails(device);
            }
        }
    }

    showDeviceTooltip(device) {
        // Tooltip is handled by vis.js automatically with node titles
    }

    showDeviceDetails(device) {
        // Create a modal or detailed view for device information
        const details = this.getDetailedDeviceInfo(device);

        // For now, show in log window - could be enhanced with a modal
        this.logMessage(`=== Device Details: ${device.hostname || device.ip} ===`, 'info');
        this.logMessage(`IP Address: ${device.ip}`, 'info');
        this.logMessage(`MAC Address: ${device.mac}`, 'info');
        this.logMessage(`Vendor: ${device.vendor}`, 'info');
        if (device.hostname && device.hostname !== 'Unknown') {
            this.logMessage(`Hostname: ${device.hostname}`, 'info');
        }
        this.logMessage(`Device Type: ${this.getDeviceType(device)}`, 'info');

        if (device.ports && device.ports.length > 0) {
            this.logMessage(`Open Ports (${device.ports.length}):`, 'info');
            device.ports.forEach(port => {
                this.logMessage(`  ${port.port}/${port.service} (${port.state})`, 'info');
            });
        } else {
            this.logMessage('No open ports detected', 'info');
        }
        this.logMessage('=== End Device Details ===', 'info');
    }

    getDetailedDeviceInfo(device) {
        return {
            ip: device.ip,
            mac: device.mac,
            vendor: device.vendor,
            hostname: device.hostname,
            type: this.getDeviceType(device),
            ports: device.ports || []
        };
    }

    async startScan() {
        const scanButton = document.getElementById('scan-button');
        const target = document.getElementById('target').value;
        const scanType = document.getElementById('scan-type').value;
        const timing = document.getElementById('timing').value;
        const additional = document.getElementById('additional-options').value;
        const thoroughScan = document.getElementById('thorough-scan').checked;

        if (!target) {
            this.logMessage('Error: Target network is required', 'error');
            return;
        }

        // Reset graph initialization for new scan
        this.graphInitialized = false;
        this.lastLogContent = '';
        this.lastScanStatus = null;

        // Build NMAP options
        let options = scanType;
        if (timing) options += ' ' + timing;
        if (additional) options += ' ' + additional;

        scanButton.disabled = true;
        scanButton.textContent = 'Scanning...';
        scanButton.classList.add('loading');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    options: options.trim(),
                    thorough: thoroughScan
                })
            });

            const result = await response.json();

            if (response.ok) {
                this.logMessage(`Scan started on ${target} with options: ${options}${thoroughScan ? ' (thorough mode)' : ''}`, 'success');
            } else {
                this.logMessage(`Error: ${result.error}`, 'error');
            }
        } catch (error) {
            this.logMessage(`Network error: ${error.message}`, 'error');
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = 'Start Scan';
            scanButton.classList.remove('loading');
        }
    }

    startStatusUpdates() {
        this.scanInterval = setInterval(() => this.updateScanStatus(), 2000);
    }

    async updateScanStatus() {
        try {
            const response = await fetch('/api/scan/status');
            const status = await response.json();

            // Only update log if content has changed
            const currentLogContent = status.output.join('\n');
            if (currentLogContent !== this.lastLogContent) {
                const logOutput = document.getElementById('log-output');
                logOutput.textContent = currentLogContent;
                this.lastLogContent = currentLogContent;

                // Auto-scroll to bottom only when content changes
                logOutput.scrollTop = logOutput.scrollHeight;
            }

            // Only load devices once when scan completes (not continuously)
            const scanCompleted = !status.in_progress && status.output.some(line => line.includes('Scan completed'));
            const scanWasInProgress = this.lastScanStatus === true;

            if (scanCompleted && scanWasInProgress && !this.graphInitialized) {
                this.loadDevices();
                this.graphInitialized = true;
            }

            this.lastScanStatus = status.in_progress;
        } catch (error) {
            console.error('Failed to update scan status:', error);
        }
    }

    async loadDevices() {
        try {
            const response = await fetch('/api/devices');
            const data = await response.json();
            this.devices = data.devices || [];
            this.updateNetworkGraph();
        } catch (error) {
            console.error('Failed to load devices:', error);
        }
    }

    updateNetworkGraph() {
        const nodes = [];
        const edges = [];

        // Create router/gateway node at the top
        const gatewayNode = {
            id: 'gateway',
            label: 'Internet Gateway\nRouter',
            title: 'Network Gateway/Router - Main network access point',
            shape: 'box',
            color: {
                background: '#0a0a0a',
                border: '#00ffff'
            },
            font: {
                color: '#00ffff',
                size: 14,
                align: 'center'
            },
            level: 0 // Top level in hierarchy
        };
        nodes.push(gatewayNode);

        // Group devices by type for better organization
        const deviceGroups = {
            routers: [],
            switches: [],
            servers: [],
            computers: [],
            mobile: [],
            iot: []
        };

        this.devices.forEach((device) => {
            const deviceType = device.device_type || this.getDeviceType(device);
            switch(deviceType) {
                case 'router':
                    deviceGroups.routers.push(device);
                    break;
                case 'server':
                    deviceGroups.servers.push(device);
                    break;
                case 'mobile':
                    deviceGroups.mobile.push(device);
                    break;
                case 'iot':
                    deviceGroups.iot.push(device);
                    break;
                default:
                    deviceGroups.computers.push(device);
            }
        });

        // Create intermediate switch nodes for organization
        let level = 1;
        const switchNodes = [];

        // Create switch for computers
        if (deviceGroups.computers.length > 0) {
            const switchNode = {
                id: 'switch-computers',
                label: 'Switch\n(Computers)',
                title: 'Network Switch - Computer devices',
                shape: 'box',
                color: {
                    background: '#0a0a0a',
                    border: '#00aaaa'
                },
                font: {
                    color: '#00aaaa',
                    size: 12,
                    align: 'center'
                },
                level: level
            };
            nodes.push(switchNode);
            switchNodes.push('switch-computers');

            edges.push({
                from: 'gateway',
                to: 'switch-computers',
                color: '#00ffff',
                width: 3,
                label: 'LAN'
            });
        }

        // Create switch for mobile/IoT devices
        if (deviceGroups.mobile.length > 0 || deviceGroups.iot.length > 0) {
            const switchNode = {
                id: 'switch-wireless',
                label: 'Wireless\nAccess Point',
                title: 'Wireless Access Point - Mobile and IoT devices',
                shape: 'box',
                color: {
                    background: '#0a0a0a',
                    border: '#00aaaa'
                },
                font: {
                    color: '#00aaaa',
                    size: 12,
                    align: 'center'
                },
                level: level
            };
            nodes.push(switchNode);
            switchNodes.push('switch-wireless');

            edges.push({
                from: 'gateway',
                to: 'switch-wireless',
                color: '#00ffff',
                width: 3,
                label: 'WiFi'
            });
        }

        // Create switch for servers
        if (deviceGroups.servers.length > 0) {
            const switchNode = {
                id: 'switch-servers',
                label: 'Server\nSwitch',
                title: 'Server Switch - Network servers',
                shape: 'box',
                color: {
                    background: '#0a0a0a',
                    border: '#00aaaa'
                },
                font: {
                    color: '#00aaaa',
                    size: 12,
                    align: 'center'
                },
                level: level
            };
            nodes.push(switchNode);
            switchNodes.push('switch-servers');

            edges.push({
                from: 'gateway',
                to: 'switch-servers',
                color: '#00ffff',
                width: 3,
                label: 'DMZ'
            });
        }

        level = 2;

        // Add computer devices
        deviceGroups.computers.forEach((device, index) => {
            const node = this.createDeviceNode(device, level, index);
            nodes.push(node);
            edges.push({
                from: 'switch-computers',
                to: device.ip,
                color: '#00ffff',
                width: 2
            });
        });

        // Add mobile/IoT devices
        [...deviceGroups.mobile, ...deviceGroups.iot].forEach((device, index) => {
            const node = this.createDeviceNode(device, level, index);
            nodes.push(node);
            edges.push({
                from: 'switch-wireless',
                to: device.ip,
                color: '#00ffff',
                width: 2
            });
        });

        // Add server devices
        deviceGroups.servers.forEach((device, index) => {
            const node = this.createDeviceNode(device, level, index);
            nodes.push(node);
            edges.push({
                from: 'switch-servers',
                to: device.ip,
                color: '#00ffff',
                width: 2
            });
        });

        // Add router devices directly to gateway
        deviceGroups.routers.forEach((device, index) => {
            const node = this.createDeviceNode(device, 1, index);
            nodes.push(node);
            edges.push({
                from: 'gateway',
                to: device.ip,
                color: '#00ffff',
                width: 3,
                label: 'WAN'
            });
        });

        // Update the network
        this.network.setData({
            nodes: new vis.DataSet(nodes),
            edges: new vis.DataSet(edges)
        });

        // Fit the view
        setTimeout(() => {
            this.network.fit();
        }, 100);
    }

    createDeviceNode(device, level, index) {
        const deviceType = device.device_type || this.getDeviceType(device);
        const shape = this.getDeviceShape(deviceType);
        const icon = this.getDeviceIcon(deviceType);

        // Use grey styling for unidentified devices
        const isIdentified = device.identified !== false;
        const borderColor = isIdentified ? '#00ffff' : '#666666';
        const backgroundColor = isIdentified ? '#0a0a0a' : '#333333';
        const fontColor = isIdentified ? '#00ffff' : '#cccccc';

        return {
            id: device.ip,
            label: this.getDeviceLabel(device),
            title: this.getDeviceTooltip(device),
            shape: shape,
            color: {
                background: backgroundColor,
                border: borderColor
            },
            font: {
                color: fontColor,
                size: 11,
                align: 'center'
            },
            level: level,
            icon: icon ? {
                face: 'FontAwesome',
                code: icon,
                size: 16,
                color: fontColor
            } : undefined
        };
    }

    getDeviceType(device) {
        const vendor = device.vendor.toLowerCase();
        const hostname = (device.hostname || '').toLowerCase();

        if (vendor.includes('apple') || hostname.includes('iphone') || hostname.includes('ipad') || hostname.includes('mac')) {
            return 'apple';
        } else if (vendor.includes('roku') || hostname.includes('roku')) {
            return 'roku';
        } else if (vendor.includes('tp-link') || vendor.includes('netgear') || vendor.includes('d-link') || vendor.includes('linksys')) {
            return 'router';
        } else if (vendor.includes('google') || hostname.includes('chromecast') || hostname.includes('nest')) {
            return 'google';
        } else if (device.ports.some(p => p.port === 80 || p.port === 443 || p.port === 22)) {
            return 'server';
        } else {
            return 'computer';
        }
    }

    getDeviceShape(type) {
        const shapes = {
            'router': 'diamond', // Router symbol
            'server': 'square', // Server rack
            'apple': 'circle', // Mobile device
            'roku': 'triangle', // IoT device
            'google': 'triangle', // IoT device
            'computer': 'square' // Desktop computer
        };
        return shapes[type] || 'square';
    }

    getDeviceIcon(type) {
        const icons = {
            'apple': '\uf179', // Apple icon
            'roku': '\uf26c', // TV icon
            'router': '\uf0ec', // Sitemap icon
            'google': '\uf1a0', // Circle icon
            'server': '\uf233', // Server icon
            'computer': '\uf108' // Desktop icon
        };
        return icons[type] || icons['computer'];
    }

    getDeviceLabel(device) {
        if (device.hostname && device.hostname !== 'Unknown') {
            // Show hostname, but limit length for display
            const hostname = device.hostname.length > 12 ?
                device.hostname.substring(0, 10) + '...' : device.hostname;
            return hostname;
        }
        // Show IP address for devices without hostname
        return device.ip;
    }

    getDeviceTooltip(device) {
        let tooltip = `<div style="font-family: Courier New; color: #00ff00;">`;
        tooltip += `<strong>IP:</strong> ${device.ip}<br>`;
        tooltip += `<strong>MAC:</strong> ${device.mac}<br>`;
        tooltip += `<strong>Vendor:</strong> ${device.vendor}<br>`;
        if (device.hostname && device.hostname !== 'Unknown') {
            tooltip += `<strong>Hostname:</strong> ${device.hostname}<br>`;
        }
        if (device.ports && device.ports.length > 0) {
            tooltip += `<strong>Open Ports:</strong><br>`;
            device.ports.slice(0, 5).forEach(port => {
                tooltip += `  ${port.port}/${port.service}<br>`;
            });
            if (device.ports.length > 5) {
                tooltip += `  ... and ${device.ports.length - 5} more<br>`;
            }
        }
        tooltip += `</div>`;
        return tooltip;
    }

    logMessage(message, type = 'info') {
        const logOutput = document.getElementById('log-output');
        const timestamp = new Date().toLocaleTimeString();
        const formattedMessage = `[${timestamp}] ${message}`;

        logOutput.textContent += (logOutput.textContent ? '\n' : '') + formattedMessage;
        logOutput.scrollTop = logOutput.scrollHeight;

        // Add CSS class for styling
        const lines = logOutput.textContent.split('\n');
        const lastLine = lines[lines.length - 1];
        if (type === 'error') {
            logOutput.innerHTML = lines.slice(0, -1).join('\n') + '\n' +
                `<span class="status-error">${lastLine}</span>`;
        } else if (type === 'success') {
            logOutput.innerHTML = lines.slice(0, -1).join('\n') + '\n' +
                `<span class="status-success">${lastLine}</span>`;
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new WireInterpreter();
});

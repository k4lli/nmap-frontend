// Wire Interpreter - NMAP Network Scanner Frontend
class WireInterpreter {
    constructor() {
        this.network = null;
        this.devices = [];
        this.scanInterval = null;
        this.lastLogContent = '';
        this.lastScanStatus = null;
        this.graphInitialized = false;
        this.selectedTags = new Set();
        this.init();
    }

    init() {
        this.bindEvents();
        this.initializeGraph();
        this.checkApiKeyStatus();
    }

    bindEvents() {
        const scanButton = document.getElementById('scan-button');
        const targetInput = document.getElementById('target');
        const scanTypeSelect = document.getElementById('scan-type');
        const timingSelect = document.getElementById('timing');
        const additionalOptions = document.getElementById('additional-options');
        const thoroughScanCheckbox = document.getElementById('thorough-scan');
        const logPanel = document.getElementById('log-panel');
        const saveScanBtn = document.getElementById('save-scan-btn');
        const loadScanBtn = document.getElementById('load-scan-btn');

        scanButton.addEventListener('click', () => this.startScan());
        logPanel.addEventListener('click', () => this.showLogViewer());
        saveScanBtn.addEventListener('click', () => this.saveScan());
        loadScanBtn.addEventListener('click', () => this.loadScan());

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
                this.showDeviceDetailsPanel(device);
            }
        }
    }

    showDeviceTooltip(device) {
        // Tooltip is handled by vis.js automatically with node titles
    }

    showDeviceDetailsPanel(device) {
        const panel = document.getElementById('device-details-panel');
        const title = document.getElementById('device-details-title');
        const content = document.getElementById('device-details-content');

        // Set device title
        title.textContent = device.hostname && device.hostname !== 'Unknown' ? device.hostname : device.ip;

        // Create detailed content
        const deviceType = this.getDeviceType(device);
        const deviceIcon = this.getDeviceIcon(deviceType);

        content.innerHTML = `
            <div class="device-overview">
                <div class="device-icon">
                    ${device.logo_url ? `<img src="${device.logo_url}" alt="${device.vendor} logo" class="vendor-logo-large">` : `<i class="fas ${deviceIcon}"></i>`}
                </div>
                <div class="device-basic-info">
                    <div class="info-row">
                        <span class="label">IP Address:</span>
                        <span class="value">${device.ip}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">MAC Address:</span>
                        <span class="value">${device.mac}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Vendor:</span>
                        <span class="value">${device.vendor}</span>
                    </div>
                    ${device.hostname && device.hostname !== 'Unknown' ?
                        `<div class="info-row">
                            <span class="label">Hostname:</span>
                            <span class="value">${device.hostname}</span>
                        </div>` : ''}
                    <div class="info-row">
                        <span class="label">Device Type:</span>
                        <span class="value">${deviceType.charAt(0).toUpperCase() + deviceType.slice(1)}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Status:</span>
                        <span class="value status-${device.state}">${device.state}</span>
                    </div>
                    ${device.os_info && device.os_info !== 'Unknown' ?
                        `<div class="info-row">
                            <span class="label">OS Info:</span>
                            <span class="value">${device.os_info}${device.os_accuracy ? ` (${device.os_accuracy}% accuracy)` : ''}${device.os_family && device.os_family !== 'Unknown' ? ` - ${device.os_family}` : ''}</span>
                        </div>` : ''}
                </div>
            </div>

            ${device.tags && device.tags.length > 0 ? `
                <div class="device-tags">
                    <h4>Tags</h4>
                    <div class="tags-list">
                        ${device.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                </div>
            ` : ''}

            ${device.ports && device.ports.length > 0 ? `
                <div class="device-ports">
                    <h4>Open Ports (${device.ports.length})</h4>
                    <div class="ports-grid">
                        ${device.ports.map((port, index) => `
                            <div class="port-item clickable" onclick="window.wireInterpreter.showServiceDetails('${device.ip}', ${index})">
                                <div class="port-number">${port.port}</div>
                                <div class="port-service">${port.service}</div>
                                <div class="port-state status-${port.state}">${port.state}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : `
                <div class="no-ports">
                    <i class="fas fa-info-circle"></i>
                    <p>No open ports detected</p>
                </div>
            `}
        `;

        // Show the panel with animation
        panel.classList.add('active');

        // Add close button event listener
        document.getElementById('close-details-btn').onclick = () => {
            this.hideDeviceDetailsPanel();
        };

        // Close on outside click
        panel.onclick = (e) => {
            if (e.target === panel) {
                this.hideDeviceDetailsPanel();
            }
        };
    }

    hideDeviceDetailsPanel() {
        const panel = document.getElementById('device-details-panel');
        panel.classList.remove('active');
    }

    showServiceDetails(deviceIp, portIndex) {
        const device = this.devices.find(d => d.ip === deviceIp);
        if (!device || !device.ports || !device.ports[portIndex]) {
            console.error('Device or port not found');
            return;
        }

        const port = device.ports[portIndex];
        const panel = document.getElementById('service-details-panel');
        const title = document.getElementById('service-details-title');
        const content = document.getElementById('service-details-content');

        // Set service title
        title.textContent = `${port.service} on port ${port.port} (${device.hostname || device.ip})`;

        // Create detailed service content
        let serviceContent = `
            <div class="service-overview">
                <div class="service-basic-info">
                    <div class="info-row">
                        <span class="label">Port:</span>
                        <span class="value">${port.port}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Service:</span>
                        <span class="value">${port.service}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">State:</span>
                        <span class="value status-${port.state}">${port.state}</span>
                    </div>
        `;

        if (port.version && port.version !== '') {
            serviceContent += `
                    <div class="info-row">
                        <span class="label">Version:</span>
                        <span class="value">${port.version}</span>
                    </div>
            `;
        }

        if (port.product && port.product !== '') {
            serviceContent += `
                    <div class="info-row">
                        <span class="label">Product:</span>
                        <span class="value">${port.product}</span>
                    </div>
            `;
        }

        if (port.extrainfo && port.extrainfo !== '') {
            serviceContent += `
                    <div class="info-row">
                        <span class="label">Extra Info:</span>
                        <span class="value">${port.extrainfo}</span>
                    </div>
            `;
        }

        serviceContent += `
                </div>
            </div>
        `;

        // Add CPE information if available
        if (port.cpe && port.cpe.length > 0) {
            serviceContent += `
                <div class="service-cpe">
                    <h4>CPE Information</h4>
                    <div class="cpe-list">
                        ${port.cpe.map(cpe => `<div class="cpe-item">${cpe}</div>`).join('')}
                    </div>
                </div>
            `;
        }

        // Add script output (banner grabbing results) if available
        if (port.scripts && Object.keys(port.scripts).length > 0) {
            serviceContent += `
                <div class="service-scripts">
                    <h4>Script Output (Banner Information)</h4>
                    <div class="scripts-content">
            `;

            for (const [scriptName, scriptOutput] of Object.entries(port.scripts)) {
                serviceContent += `
                        <div class="script-item">
                            <h5>${scriptName}</h5>
                            <pre class="script-output">${scriptOutput}</pre>
                        </div>
                `;
            }

            serviceContent += `
                    </div>
                </div>
            `;
        }

        content.innerHTML = serviceContent;

        // Show the panel with animation
        panel.classList.add('active');

        // Add close button event listener
        document.getElementById('close-service-btn').onclick = () => {
            this.hideServiceDetailsPanel();
        };

        // Close on outside click
        panel.onclick = (e) => {
            if (e.target === panel) {
                this.hideServiceDetailsPanel();
            }
        };
    }

    hideServiceDetailsPanel() {
        const panel = document.getElementById('service-details-panel');
        panel.classList.remove('active');
    }

    async showLogViewer() {
        const panel = document.getElementById('log-viewer-panel');
        const content = document.getElementById('log-viewer-content');

        try {
            // Get the full log from the backend
            const response = await fetch('/api/scan/log');
            const data = await response.json();

            // Format the log content
            const logContent = data.log.join('\n');

            // Display the full log
            content.innerHTML = `<pre class="full-log-content">${logContent}</pre>`;

            // Show the panel with animation
            panel.classList.add('active');

            // Add close button event listener
            document.getElementById('close-log-btn').onclick = () => {
                this.hideLogViewer();
            };

            // Add export button event listener
            document.getElementById('export-log-btn').onclick = () => {
                this.exportLog(logContent);
            };

            // Close on outside click
            panel.onclick = (e) => {
                if (e.target === panel) {
                    this.hideLogViewer();
                }
            };

        } catch (error) {
            console.error('Failed to load log:', error);
            content.innerHTML = `<div class="log-error">Failed to load log content</div>`;
            panel.classList.add('active');
        }
    }

    hideLogViewer() {
        const panel = document.getElementById('log-viewer-panel');
        panel.classList.remove('active');
    }

    exportLog(logContent) {
        // Create a blob with the log content
        const blob = new Blob([logContent], { type: 'text/plain' });

        // Create a temporary download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nmap-scan-log-${new Date().toISOString().split('T')[0]}.txt`;

        // Trigger the download
        document.body.appendChild(a);
        a.click();

        // Clean up
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
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

        // Stop any existing status polling
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
            this.scanInterval = null;
        }

        // Clear the log output and reset state
        const logOutput = document.getElementById('log-output');
        logOutput.textContent = '';

        // Clear the network graph
        if (this.network) {
            this.network.setData({ nodes: [], edges: [] });
        }

        // Reset graph initialization for new scan
        this.graphInitialized = false;
        this.lastLogContent = '';
        this.lastScanStatus = null;
        this.devices = [];

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
                // Start status updates when scan begins
                this.startStatusUpdates();
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
            this.updateTagFilters();
            this.updateNetworkGraph();
        } catch (error) {
            console.error('Failed to load devices:', error);
        }
    }

    updateTagFilters() {
        const allTags = new Set();
        this.devices.forEach(device => {
            if (device.tags) {
                device.tags.forEach(tag => allTags.add(tag));
            }
        });
        const sortedTags = Array.from(allTags).sort();
        const tagFilters = document.getElementById('tag-filters');
        tagFilters.innerHTML = '';
        sortedTags.forEach(tag => {
            const label = document.createElement('label');
            label.className = 'tag-filter';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = tag;
            checkbox.checked = this.selectedTags.has(tag);
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    this.selectedTags.add(tag);
                } else {
                    this.selectedTags.delete(tag);
                }
                this.updateNetworkGraph();
            });
            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(' ' + tag));
            tagFilters.appendChild(label);
        });
    }

    updateNetworkGraph() {
        // Filter devices based on selected tags
        const filteredDevices = this.selectedTags.size > 0 ?
            this.devices.filter(device => device.tags && device.tags.some(tag => this.selectedTags.has(tag))) :
            this.devices;

        const nodes = [];
        const edges = [];

        // Find routers in filtered devices
        const routers = filteredDevices.filter(d => d.device_type === 'router');

        if (routers.length > 0) {
            // Use the first router as the main gateway
            const mainRouter = routers[0];
            nodes.push(this.createDeviceNode(mainRouter, 0));

            // Add all other devices connected to the main router
            const otherDevices = filteredDevices.filter(d => d.ip !== mainRouter.ip);
            otherDevices.forEach((device) => {
                nodes.push(this.createDeviceNode(device, 1));
                edges.push({
                    from: mainRouter.ip,
                    to: device.ip,
                    color: '#00ffff',
                    width: 2
                });
            });
        } else {
            // No router found, show all devices at same level
            filteredDevices.forEach((device) => {
                nodes.push(this.createDeviceNode(device, 0));
            });
        }

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

        const node = {
            id: device.ip,
            label: this.getDeviceLabel(device),
            title: this.getDeviceTooltip(device),
            color: {
                background: backgroundColor,
                border: borderColor
            },
            font: {
                color: fontColor,
                size: 11,
                align: 'center'
            },
            level: level
        };

        if (device.logo_url) {
            console.log(`Using logo for ${device.vendor}: ${device.logo_url}`);
            node.shape = 'image';
            node.image = device.logo_url;
            node.size = 30;
            // Add error handling for image loading
            node.brokenImage = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAiIGhlaWdodD0iMzAiIHZpZXdCb3g9IjAgMCAzMCAzMCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iMTUiIGN5PSIxNSIgcj0iMTUiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iIzAwZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+Cjx0ZXh0IHg9IjE1IiB5PSIyMCIgZm9udC1mYW1pbHk9IkFyaWFsLCBzYW5zLXNlcmlmIiBmb250LXNpemU9IjE0IiBmaWxsPSIjMDBmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5JPPC90ZXh0Pgo8L3N2Zz4=';
        } else {
            console.log(`No logo for ${device.vendor}, using icon: ${icon}`);
            node.shape = shape;
            node.icon = icon ? {
                face: 'FontAwesome',
                code: icon,
                size: 16,
                color: fontColor
            } : undefined;
        }

        return node;
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
        if (device.tags && device.tags.length > 0) {
            tooltip += `<strong>Tags:</strong> ${device.tags.join(', ')}<br>`;
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

    async saveScan() {
        try {
            const response = await fetch('/api/save_scan');
            if (response.ok) {
                const data = await response.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `nmap-scan-${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                URL.revokeObjectURL(url);
                this.logMessage('Scan data saved successfully', 'success');
            } else {
                this.logMessage('Failed to save scan data', 'error');
            }
        } catch (error) {
            this.logMessage(`Error saving scan: ${error.message}`, 'error');
        }
    }

    async loadScan() {
        const fileInput = document.getElementById('load-scan-file');
        fileInput.click();
        fileInput.onchange = async (e) => {
            const file = e.target.files[0];
            if (file) {
                const formData = new FormData();
                formData.append('file', file);
                try {
                    const response = await fetch('/api/load_scan', {
                        method: 'POST',
                        body: formData
                    });
                    if (response.ok) {
                        const data = await response.json();
                        this.devices = data.devices || [];
                        this.updateTagFilters();
                        this.updateNetworkGraph();
                        this.logMessage('Scan data loaded successfully', 'success');
                    } else {
                        const error = await response.json();
                        this.logMessage(`Failed to load scan: ${error.error}`, 'error');
                    }
                } catch (error) {
                    this.logMessage(`Error loading scan: ${error.message}`, 'error');
                }
            }
        };
    }

    async checkApiKeyStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();

            if (!status.api_key_exists) {
                this.showApiKeyAlert();
            } else {
                this.hideApiKeyAlert();
            }
        } catch (error) {
            console.error('Failed to check API key status:', error);
            // Show alert on error to be safe
            this.showApiKeyAlert();
        }
    }

    showApiKeyAlert() {
        const alert = document.getElementById('api-key-alert');
        alert.style.display = 'block';
    }

    hideApiKeyAlert() {
        const alert = document.getElementById('api-key-alert');
        alert.style.display = 'none';
    }

    logMessage(message, type = 'info') {
        const logOutput = document.getElementById('log-output');
        const now = new Date();
        const timestamp = now.toLocaleTimeString();
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

// Global function for hiding API key alert (called from HTML)
function hideApiKeyAlert() {
    const alert = document.getElementById('api-key-alert');
    if (alert) {
        alert.style.display = 'none';
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.wireInterpreter = new WireInterpreter();
});

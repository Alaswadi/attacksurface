/**
 * Real Security Scanning JavaScript
 */

// Global variables
let currentScan = null;
let scanInterval = null;

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Check tool status on page load
    checkToolStatus();

    // Setup custom port range toggle
    const naabuPorts = document.getElementById('naabuPorts');
    if (naabuPorts) {
        naabuPorts.addEventListener('change', function() {
            const customPortRange = document.getElementById('customPortRange');
            if (this.value === 'custom') {
                customPortRange.style.display = 'block';
            } else {
                customPortRange.style.display = 'none';
            }
        });
    }
});

/**
 * Check security tools status
 */
function checkToolStatus() {
    showLoading('Checking security tools status...');

    fetch('/api/scan/status')
        .then(response => {
            console.log('Tool status response:', response.status, response.statusText);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Tool status data:', data);
            hideLoading();
            if (data.success) {
                displayToolStatus(data.status);
            } else {
                showError('Failed to check tool status: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Tool status error:', error);
            hideLoading();
            showError('Error checking tool status: ' + error.message);
        });
}

/**
 * Display tool status
 */
function displayToolStatus(status) {
    const toolStatusCard = document.getElementById('toolStatusCard');
    const toolStatusContent = document.getElementById('toolStatusContent');

    let html = '<div class="grid grid-cols-1 md:grid-cols-3 gap-4">';

    // Available tools
    const tools = status.available_tools;
    const versions = status.tool_versions;

    Object.keys(tools).forEach(tool => {
        const isAvailable = tools[tool];
        const version = versions[tool] || 'Unknown';
        const statusClass = isAvailable ? 'green' : 'red';
        const statusIcon = isAvailable ? 'check-line' : 'close-line';
        const statusText = isAvailable ? 'Available' : 'Not Available';

        html += `
            <div class="border border-gray-200 rounded-lg p-4 text-center">
                <i class="ri-${statusIcon} text-2xl text-${statusClass}-500 mb-2"></i>
                <h3 class="text-lg font-semibold capitalize mb-2">${tool}</h3>
                <span class="inline-block px-3 py-1 text-sm rounded-full ${isAvailable ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">${statusText}</span>
                <p class="text-sm text-gray-600 mt-2">Version: ${version}</p>
            </div>
        `;
    });

    html += '</div>';

    // Add test tools button
    html += `
        <div class="text-center mt-6">
            <button class="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors" onclick="testTools()">
                <i class="ri-test-tube-line mr-2"></i> Test All Tools
            </button>
        </div>
    `;

    toolStatusContent.innerHTML = html;
    toolStatusCard.classList.remove('hidden');
}

/**
 * Test all security tools
 */
function testTools() {
    showLoading('Testing security tools...');
    
    $.ajax({
        url: '/api/scan/test-tools',
        method: 'POST',
        success: function(response) {
            hideLoading();
            if (response.success) {
                displayTestResults(response.test_results);
            } else {
                showError('Failed to test tools: ' + response.error);
            }
        },
        error: function(xhr, status, error) {
            hideLoading();
            showError('Error testing tools: ' + error);
        }
    });
}

/**
 * Display test results
 */
function displayTestResults(results) {
    let html = '<h6>Tool Test Results:</h6><ul class="list-group">';
    
    Object.keys(results).forEach(tool => {
        const result = results[tool];
        const statusClass = result.status === 'working' ? 'success' : 
                           result.status === 'error' ? 'danger' : 'warning';
        const statusIcon = result.status === 'working' ? 'check' : 
                          result.status === 'error' ? 'times' : 'exclamation';
        
        html += `
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <span>
                    <i class="fas fa-${statusIcon} text-${statusClass}"></i>
                    ${tool.charAt(0).toUpperCase() + tool.slice(1)}
                </span>
                <span class="badge badge-${statusClass}">${result.status}</span>
            </li>
        `;
        
        if (result.error) {
            html += `<li class="list-group-item"><small class="text-danger">Error: ${result.error}</small></li>`;
        }
    });
    
    html += '</ul>';
    
    showInfo(html);
}

/**
 * Start quick scan
 */
function startQuickScan() {
    const domain = document.getElementById('quickScanDomain').value.trim();
    if (!domain) {
        showError('Please enter a domain to scan');
        return;
    }

    startScan(domain, 'quick');
}

/**
 * Start deep scan
 */
function startDeepScan() {
    const domain = document.getElementById('deepScanDomain').value.trim();
    if (!domain) {
        showError('Please enter a domain to scan');
        return;
    }

    startScan(domain, 'deep');
}

/**
 * Show custom scan modal
 */
function showCustomScanModal() {
    const domain = document.getElementById('customScanDomain').value.trim();
    if (!domain) {
        showError('Please enter a domain to scan');
        return;
    }

    // For now, just start a custom scan directly since we don't have a modal
    startScan(domain, 'custom');
}

/**
 * Start custom scan
 */
function startCustomScan() {
    const domain = $('#customScanDomain').val().trim();
    if (!domain) {
        showError('Please enter a domain to scan');
        return;
    }
    
    // Build custom configuration
    const config = {
        subfinder: {
            max_time: parseInt($('#subfinderMaxTime').val()) || 180,
            recursive: $('#subfinderRecursive').is(':checked')
        },
        naabu: {
            rate: parseInt($('#naabuRate').val()) || 1000
        },
        nuclei: {
            rate_limit: parseInt($('#nucleiRateLimit').val()) || 150
        }
    };
    
    // Handle port configuration
    const portSelection = $('#naabuPorts').val();
    if (portSelection === 'custom') {
        config.naabu.ports = $('#customPorts').val();
    } else if (portSelection.startsWith('top-')) {
        config.naabu.top_ports = parseInt(portSelection.split('-')[1]);
    } else {
        config.naabu.ports = portSelection;
    }
    
    // Handle severity selection
    const severities = [];
    if ($('#severityCritical').is(':checked')) severities.push('critical');
    if ($('#severityHigh').is(':checked')) severities.push('high');
    if ($('#severityMedium').is(':checked')) severities.push('medium');
    if ($('#severityLow').is(':checked')) severities.push('low');
    if ($('#severityInfo').is(':checked')) severities.push('info');
    
    if (severities.length > 0) {
        config.nuclei.severity = severities;
    }
    
    $('#customScanModal').modal('hide');
    startScan(domain, 'custom', config);
}

/**
 * Start scan with specified type
 */
function startScan(domain, scanType, config = null) {
    showScanProgress();

    const data = {
        domain: domain,
        scan_type: scanType
    };

    if (config) {
        data.config = config;
    }

    const endpoint = scanType === 'custom' ? '/api/scan/custom' : `/api/scan/${scanType}`;

    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            return response.text().then(text => {
                console.error('Non-JSON response:', text);
                throw new Error('Server returned non-JSON response: ' + text.substring(0, 200));
            });
        }

        return response.json();
    })
    .then(data => {
        console.log('Scan response data:', data);
        hideScanProgress();
        if (data.success) {
            displayScanResults(data.scan_results);
            const scanTypeName = scanType ? scanType.charAt(0).toUpperCase() + scanType.slice(1) : 'Scan';
            showSuccess(`${scanTypeName} completed successfully!`);
        } else {
            showError('Scan failed: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Scan error details:', error);
        hideScanProgress();
        showError('Scan error: ' + error.message);
    });
}

/**
 * Start individual tool scans
 */
function startSubfinderScan() {
    const domain = document.getElementById('subfinderDomain').value.trim();
    if (!domain) {
        showError('Please enter a domain');
        return;
    }

    showLoading('Running Subfinder...');

    fetch('/api/scan/subdomain', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain: domain })
    })
    .then(response => {
        console.log('Subfinder response:', response.status, response.statusText);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Subfinder data:', data);
        hideLoading();
        if (data.success) {
            displayIndividualScanResults('Subfinder', data.results);
        } else {
            showError('Subfinder scan failed: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Subfinder error:', error);
        hideLoading();
        showError('Subfinder error: ' + error.message);
    });
}

function startMasscanScan() {
    const targets = document.getElementById('masscanTargets').value.trim();
    if (!targets) {
        showError('Please enter target hosts');
        return;
    }

    showLoading('Running Masscan...');

    fetch('/api/scan/ports', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            targets: targets.split(',').map(t => t.trim()),
            options: { top_ports: 100 }
        })
    })
    .then(response => {
        console.log('Masscan response:', response.status, response.statusText);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Masscan data:', data);
        hideLoading();
        if (data.success) {
            displayIndividualScanResults('Masscan', data.results);
        } else {
            showError('Masscan scan failed: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Masscan error:', error);
        hideLoading();
        showError('Masscan error: ' + error.message);
    });
}

function startNucleiScan() {
    const targets = document.getElementById('nucleiTargets').value.trim();
    if (!targets) {
        showError('Please enter target URLs');
        return;
    }

    showLoading('Running Nuclei...');

    fetch('/api/scan/vulnerabilities', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            targets: targets.split(',').map(t => t.trim()),
            options: { severity: ['critical', 'high'] }
        })
    })
    .then(response => {
        console.log('Nuclei response:', response.status, response.statusText);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Nuclei data:', data);
        hideLoading();
        if (data.success) {
            displayIndividualScanResults('Nuclei', data.results);
        } else {
            showError('Nuclei scan failed: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Nuclei error:', error);
        hideLoading();
        showError('Nuclei error: ' + error.message);
    });
}

function startHttpxScan() {
    const targets = document.getElementById('httpxTargets').value.trim();
    if (!targets) {
        showError('Please enter target hosts');
        return;
    }

    showLoading('Running Httpx...');

    fetch('/api/scan/httpx', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            targets: targets.split(',').map(t => t.trim()),
            options: { timeout: 10, threads: 50 }
        })
    })
    .then(response => {
        console.log('Httpx response:', response.status, response.statusText);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Httpx data:', data);
        hideLoading();
        if (data.success) {
            displayIndividualScanResults('Httpx', data.results);
        } else {
            showError('Httpx scan failed: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Httpx error:', error);
        hideLoading();
        showError('Httpx error: ' + error.message);
    });
}

/**
 * Display scan results
 */
function displayScanResults(results) {
    console.log('Displaying scan results:', results);

    const scanResultsCard = document.getElementById('scanResultsCard');
    const scanResultsContent = document.getElementById('scanResultsContent');

    if (!results) {
        console.error('No results provided to displayScanResults');
        return;
    }

    let html = `
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="border border-blue-200 rounded-lg p-4 text-center">
                <h3 class="text-2xl font-bold text-blue-600">${results.scan_summary?.subdomains_found || 0}</h3>
                <p class="text-gray-600">Subdomains</p>
            </div>
            <div class="border border-orange-200 rounded-lg p-4 text-center">
                <h3 class="text-2xl font-bold text-orange-600">${results.scan_summary?.ports_found || 0}</h3>
                <p class="text-gray-600">Open Ports</p>
            </div>
            <div class="border border-red-200 rounded-lg p-4 text-center">
                <h3 class="text-2xl font-bold text-red-600">${results.scan_summary?.vulnerabilities_found || 0}</h3>
                <p class="text-gray-600">Vulnerabilities</p>
            </div>
            <div class="border border-green-200 rounded-lg p-4 text-center">
                <h3 class="text-2xl font-bold text-green-600">${results.assets_created || 0}</h3>
                <p class="text-gray-600">Assets Created</p>
            </div>
        </div>
    `;
    
    // Show errors if any
    if (results.errors && results.errors.length > 0) {
        html += '<div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4"><h3 class="text-lg font-semibold text-yellow-800 mb-2">Scan Warnings:</h3><ul class="list-disc list-inside text-yellow-700">';
        results.errors.forEach(error => {
            html += `<li>${error}</li>`;
        });
        html += '</ul></div>';
    }

    // Add detailed results summary
    html += `
        <div class="bg-gray-50 rounded-lg p-4">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">Scan Summary for ${results.domain}</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                    <p class="mb-2"><span class="font-medium">Scan Type:</span> ${results.scan_type || 'Unknown'}</p>
                    <p class="mb-2"><span class="font-medium">Completion Time:</span> ${results.scan_time || 'Unknown'}</p>
                    <p class="mb-2"><span class="font-medium">Assets Created:</span> ${results.assets_created || 0}</p>
                </div>
                <div>
                    <p class="mb-2"><span class="font-medium">Vulnerabilities Found:</span> ${results.vulnerabilities_created || 0}</p>
                    <p class="mb-2"><span class="font-medium">Alerts Generated:</span> ${results.alerts_created || 0}</p>
                    <p class="mb-2"><span class="font-medium">Status:</span> <span class="text-green-600 font-medium">Completed</span></p>
                </div>
            </div>
            <div class="mt-4 pt-4 border-t border-gray-200">
                <p class="text-gray-600">Assets and vulnerabilities have been added to your organization. Check the <a href="/dashboard" class="text-blue-600 hover:text-blue-800 underline">Dashboard</a> for detailed analysis.</p>
            </div>
        </div>
    `;

    scanResultsContent.innerHTML = html;
    scanResultsCard.classList.remove('hidden');
}

/**
 * Display individual scan results
 */
function displayIndividualScanResults(toolName, results) {
    const scanResultsCard = $('#scanResultsCard');
    const scanResultsContent = $('#scanResultsContent');
    
    let html = `<h6>${toolName} Results</h6>`;
    html += `<pre class="bg-light p-3" style="max-height: 400px; overflow-y: auto;">${JSON.stringify(results, null, 2)}</pre>`;
    
    scanResultsContent.html(html);
    scanResultsCard.show();
}

/**
 * Show scan progress
 */
function showScanProgress() {
    const scanProgressCard = document.getElementById('scanProgressCard');
    const scanProgressText = document.getElementById('scanProgressText');
    const scanProgressBar = document.getElementById('scanProgressBar');

    scanProgressCard.classList.remove('hidden');
    scanProgressText.textContent = 'Starting scan...';
    scanProgressBar.style.width = '10%';

    // Simulate progress
    let progress = 10;
    scanInterval = setInterval(() => {
        progress += Math.random() * 20;
        if (progress > 90) progress = 90;
        scanProgressBar.style.width = progress + '%';

        if (progress < 30) {
            scanProgressText.textContent = 'Discovering subdomains...';
        } else if (progress < 60) {
            scanProgressText.textContent = 'Scanning ports...';
        } else {
            scanProgressText.textContent = 'Checking for vulnerabilities...';
        }
    }, 2000);
}

/**
 * Hide scan progress
 */
function hideScanProgress() {
    const scanProgressCard = document.getElementById('scanProgressCard');
    const scanProgressText = document.getElementById('scanProgressText');
    const scanProgressBar = document.getElementById('scanProgressBar');

    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
    scanProgressBar.style.width = '100%';
    scanProgressText.textContent = 'Scan completed!';
    setTimeout(() => {
        scanProgressCard.classList.add('hidden');
    }, 2000);
}

/**
 * Utility functions
 */
function showLoading(message) {
    console.log('Loading:', message);
    // You could add a loading spinner here
}

function hideLoading() {
    console.log('Loading complete');
}

function showError(message) {
    console.error('Error:', message);
    alert('Error: ' + message);
}

function showSuccess(message) {
    console.log('Success:', message);
    alert('Success: ' + message);
}

function showInfo(message) {
    console.log('Info:', message);
    // For now, just log to console instead of alert
}

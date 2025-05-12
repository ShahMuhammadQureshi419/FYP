/**
 * APK Malware Scanner - Visualizations JavaScript
 * Handles data visualization elements for the scan results
 */

// Function to populate the results UI with analysis data
function populateResults(data) {
    if (!data) {
        console.error('No data provided to populate results');
        return;
    }
    
    // Populate file information
    populateFileInfo(data.file_info);
    
    // Populate risk level
    populateRiskLevel(data.analysis_summary);
    
    // Populate threat statistics
    populateStatistics(data);
    
    // Create threat chart
    createThreatChart(data);
    
    // Populate permissions
    populatePermissions(data.static_analysis.permissions);
    
    // Populate suspicious code patterns
    populateCodePatterns(data.static_analysis.suspicious_code_patterns);
    
    // Populate application components
    populateComponents(data.static_analysis.components);
    
    // Populate network traffic
    populateNetworkTraffic(data.dynamic_analysis.network_traffic);
    
    // Populate file operations
    populateFileOperations(data.dynamic_analysis.file_operations);
    
    // Populate suspicious behaviors
    populateBehaviors(data.dynamic_analysis.suspicious_behaviors);
    
    // Populate vulnerabilities
    populateVulnerabilities(data.vulnerabilities);
}

/**
 * Populate file information section
 */
function populateFileInfo(fileInfo) {
    if (!fileInfo) return;
    
    const fileSizeValue = document.getElementById('fileSizeValue');
    const fileHashValue = document.getElementById('fileHashValue');
    const scanDateValue = document.getElementById('scanDateValue');
    
    if (fileSizeValue) {
        fileSizeValue.textContent = formatFileSize(fileInfo.file_size);
    }
    
    if (fileHashValue) {
        fileHashValue.textContent = fileInfo.file_hash || 'N/A';
    }
    
    if (scanDateValue && fileInfo.scan_timestamp) {
        scanDateValue.textContent = new Date(fileInfo.scan_timestamp).toLocaleString();
    } else if (scanDateValue) {
        scanDateValue.textContent = 'N/A';
    }
}

/**
 * Format file size to human-readable format
 */
function formatFileSize(bytes) {
    if (!bytes || isNaN(bytes)) return 'Unknown';
    
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }
    
    return `${size.toFixed(2)} ${units[unitIndex]}`;
}

/**
 * Populate risk level section
 */
function populateRiskLevel(summary) {
    if (!summary) return;
    
    const riskMeterIndicator = document.getElementById('riskMeterIndicator');
    const riskPointer = riskMeterIndicator ? riskMeterIndicator.querySelector('.risk-pointer') : null;
    const riskValue = document.getElementById('riskValue');
    
    // Default to a "waiting" state if no malware_detected property
    if (summary.malware_detected === null || summary.malware_detected === undefined) {
        if (riskValue) {
            riskValue.textContent = 'Waiting for backend data';
            riskValue.style.color = 'var(--cyber-text-secondary)';
        }
        return;
    }
    
    // Get risk level
    let riskLevel = summary.risk_level;
    let riskText = 'Unknown';
    let riskColor = 'var(--cyber-text-secondary)';
    let pointerPosition = '0%';
    
    // Configure based on risk level (handling both string and numeric values)
    if (riskLevel !== null && riskLevel !== undefined) {
        if (typeof riskLevel === 'string') {
            switch (riskLevel.toLowerCase()) {
                case 'safe':
                    riskText = 'Safe';
                    riskColor = 'var(--risk-safe)';
                    pointerPosition = '0%';
                    break;
                case 'low':
                    riskText = 'Low Risk';
                    riskColor = 'var(--risk-low)';
                    pointerPosition = '25%';
                    break;
                case 'medium':
                    riskText = 'Medium Risk';
                    riskColor = 'var(--risk-medium)';
                    pointerPosition = '50%';
                    break;
                case 'high':
                    riskText = 'High Risk';
                    riskColor = 'var(--risk-high)';
                    pointerPosition = '75%';
                    break;
                case 'critical':
                    riskText = 'Critical Risk';
                    riskColor = 'var(--risk-critical)';
                    pointerPosition = '100%';
                    break;
            }
        } else if (typeof riskLevel === 'number') {
            // Convert numeric risk level (assuming 0-100 scale)
            pointerPosition = `${riskLevel}%`;
            
            if (riskLevel < 20) {
                riskText = 'Safe';
                riskColor = 'var(--risk-safe)';
            } else if (riskLevel < 40) {
                riskText = 'Low Risk';
                riskColor = 'var(--risk-low)';
            } else if (riskLevel < 70) {
                riskText = 'Medium Risk';
                riskColor = 'var(--risk-medium)';
            } else if (riskLevel < 90) {
                riskText = 'High Risk';
                riskColor = 'var(--risk-high)';
            } else {
                riskText = 'Critical Risk';
                riskColor = 'var(--risk-critical)';
            }
        }
    } else {
        // Based on malware_detected boolean as fallback
        if (summary.malware_detected === true) {
            riskText = 'Malware Detected';
            riskColor = 'var(--risk-critical)';
            pointerPosition = '100%';
        } else {
            riskText = 'No Malware Detected';
            riskColor = 'var(--risk-safe)';
            pointerPosition = '0%';
        }
    }
    
    // Update the UI
    if (riskPointer) {
        riskPointer.style.left = pointerPosition;
    }
    
    if (riskValue) {
        riskValue.textContent = riskText;
        riskValue.style.color = riskColor;
    }
}

/**
 * Populate statistics section
 */
function populateStatistics(data) {
    if (!data) return;
    
    const permissionsCountValue = document.getElementById('permissionsCountValue');
    const suspiciousPatternsValue = document.getElementById('suspiciousPatternsValue');
    const vulnerabilitiesValue = document.getElementById('vulnerabilitiesValue');
    const networkActivitiesValue = document.getElementById('networkActivitiesValue');
    
    if (permissionsCountValue && data.static_analysis) {
        const permissions = data.static_analysis.permissions || [];
        permissionsCountValue.textContent = permissions.length || 'N/A';
    }
    
    if (suspiciousPatternsValue && data.static_analysis) {
        const patterns = data.static_analysis.suspicious_code_patterns || [];
        suspiciousPatternsValue.textContent = patterns.length || 'N/A';
    }
    
    if (vulnerabilitiesValue) {
        const vulnerabilities = data.vulnerabilities || [];
        vulnerabilitiesValue.textContent = vulnerabilities.length || 'N/A';
    }
    
    if (networkActivitiesValue && data.dynamic_analysis) {
        const networkTraffic = data.dynamic_analysis.network_traffic || [];
        networkActivitiesValue.textContent = networkTraffic.length || 'N/A';
    }
}

/**
 * Create threat chart
 */
function createThreatChart(data) {
    const chartCanvas = document.getElementById('threatChart');
    if (!chartCanvas || !data) return;
    
    // Calculate threat categories
    let dangerousPermissions = 0;
    let suspiciousPatterns = 0;
    let networkThreats = 0;
    let fileSystemThreats = 0;
    let vulnerabilities = 0;
    
    // Count dangerous permissions (assuming permissions have a risk_level property)
    if (data.static_analysis && data.static_analysis.permissions) {
        dangerousPermissions = data.static_analysis.permissions.filter(p => 
            p.risk_level === 'high' || p.risk_level === 'critical'
        ).length;
    }
    
    // Count suspicious code patterns
    if (data.static_analysis && data.static_analysis.suspicious_code_patterns) {
        suspiciousPatterns = data.static_analysis.suspicious_code_patterns.length;
    }
    
    // Count network threats
    if (data.dynamic_analysis && data.dynamic_analysis.network_traffic) {
        networkThreats = data.dynamic_analysis.network_traffic.filter(t => 
            t.risk_level === 'high' || t.risk_level === 'critical'
        ).length;
    }
    
    // Count file system threats
    if (data.dynamic_analysis && data.dynamic_analysis.file_operations) {
        fileSystemThreats = data.dynamic_analysis.file_operations.filter(op => 
            op.risk_level === 'high' || op.risk_level === 'critical'
        ).length;
    }
    
    // Count vulnerabilities
    if (data.vulnerabilities) {
        vulnerabilities = data.vulnerabilities.length;
    }
    
    // Create chart
    const threatChart = new Chart(chartCanvas, {
        type: 'bar',
        data: {
            labels: ['Dangerous Permissions', 'Suspicious Code', 'Network Threats', 'File System Threats', 'Vulnerabilities'],
            datasets: [{
                label: 'Threat Count',
                data: [dangerousPermissions, suspiciousPatterns, networkThreats, fileSystemThreats, vulnerabilities],
                backgroundColor: [
                    'rgba(0, 229, 255, 0.7)',
                    'rgba(0, 123, 255, 0.7)',
                    'rgba(255, 193, 7, 0.7)',
                    'rgba(255, 59, 91, 0.7)',
                    'rgba(102, 16, 242, 0.7)'
                ],
                borderColor: [
                    'rgba(0, 229, 255, 1)',
                    'rgba(0, 123, 255, 1)',
                    'rgba(255, 193, 7, 1)',
                    'rgba(255, 59, 91, 1)',
                    'rgba(102, 16, 242, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(224, 224, 255, 0.8)'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(224, 224, 255, 0.8)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Populate permissions section
 */
function populatePermissions(permissions) {
    const permissionsTableBody = document.getElementById('permissionsTableBody');
    if (!permissionsTableBody) return;
    
    // Create permissions chart
    createPermissionsChart(permissions);
    
    // Clear existing content
    permissionsTableBody.innerHTML = '';
    
    if (!permissions || permissions.length === 0) {
        permissionsTableBody.innerHTML = '<tr><td colspan="3" class="text-center">No permission data available</td></tr>';
        return;
    }
    
    // Sort permissions by risk level (high to low)
    const sortedPermissions = [...permissions].sort((a, b) => {
        const riskOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'safe': 0 };
        return (riskOrder[b.risk_level] || 0) - (riskOrder[a.risk_level] || 0);
    });
    
    // Add each permission to the table
    sortedPermissions.forEach(permission => {
        const row = document.createElement('tr');
        
        // Permission name
        const nameCell = document.createElement('td');
        nameCell.textContent = permission.name || 'Unknown';
        row.appendChild(nameCell);
        
        // Risk level
        const riskCell = document.createElement('td');
        const riskSpan = document.createElement('span');
        riskSpan.className = `risk-badge risk-${permission.risk_level || 'unknown'}`;
        riskSpan.textContent = permission.risk_level ? capitalizeFirst(permission.risk_level) : 'Unknown';
        riskCell.appendChild(riskSpan);
        row.appendChild(riskCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = permission.description || 'No description available';
        row.appendChild(descCell);
        
        permissionsTableBody.appendChild(row);
    });
}

/**
 * Create permissions chart
 */
function createPermissionsChart(permissions) {
    const chartCanvas = document.getElementById('permissionsChart');
    if (!chartCanvas || !permissions || permissions.length === 0) return;
    
    // Count permissions by risk level
    const riskCounts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'safe': 0
    };
    
    permissions.forEach(permission => {
        if (permission.risk_level && riskCounts.hasOwnProperty(permission.risk_level)) {
            riskCounts[permission.risk_level]++;
        }
    });
    
    // Create chart
    const permissionsChart = new Chart(chartCanvas, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Safe'],
            datasets: [{
                data: [
                    riskCounts.critical,
                    riskCounts.high,
                    riskCounts.medium,
                    riskCounts.low,
                    riskCounts.safe
                ],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.8)',
                    'rgba(253, 126, 20, 0.8)',
                    'rgba(255, 193, 7, 0.8)',
                    'rgba(64, 203, 217, 0.8)',
                    'rgba(40, 167, 69, 0.8)'
                ],
                borderColor: [
                    'rgba(220, 53, 69, 1)',
                    'rgba(253, 126, 20, 1)',
                    'rgba(255, 193, 7, 1)',
                    'rgba(64, 203, 217, 1)',
                    'rgba(40, 167, 69, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: 'rgba(224, 224, 255, 0.8)',
                        font: {
                            family: "'Roboto', sans-serif",
                            size: 12
                        },
                        padding: 10
                    }
                }
            }
        }
    });
}

/**
 * Populate suspicious code patterns section
 */
function populateCodePatterns(patterns) {
    const codePatternTableBody = document.getElementById('codePatternTableBody');
    if (!codePatternTableBody) return;
    
    // Clear existing content
    codePatternTableBody.innerHTML = '';
    
    if (!patterns || patterns.length === 0) {
        codePatternTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No suspicious code patterns detected</td></tr>';
        return;
    }
    
    // Sort patterns by risk level (high to low)
    const sortedPatterns = [...patterns].sort((a, b) => {
        const riskOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'safe': 0 };
        return (riskOrder[b.risk_level] || 0) - (riskOrder[a.risk_level] || 0);
    });
    
    // Add each pattern to the table
    sortedPatterns.forEach(pattern => {
        const row = document.createElement('tr');
        
        // Pattern type
        const typeCell = document.createElement('td');
        typeCell.textContent = pattern.type || 'Unknown';
        row.appendChild(typeCell);
        
        // Risk level
        const riskCell = document.createElement('td');
        const riskSpan = document.createElement('span');
        riskSpan.className = `risk-badge risk-${pattern.risk_level || 'unknown'}`;
        riskSpan.textContent = pattern.risk_level ? capitalizeFirst(pattern.risk_level) : 'Unknown';
        riskCell.appendChild(riskSpan);
        row.appendChild(riskCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = pattern.description || 'No description available';
        row.appendChild(descCell);
        
        // Location
        const locCell = document.createElement('td');
        locCell.textContent = pattern.location || 'Unknown location';
        row.appendChild(locCell);
        
        codePatternTableBody.appendChild(row);
    });
}

/**
 * Populate application components section
 */
function populateComponents(components) {
    if (!components) return;
    
    // Populate activities
    populateComponentList('activitiesList', components.activities);
    
    // Populate services
    populateComponentList('servicesList', components.services);
    
    // Populate receivers
    populateComponentList('receiversList', components.receivers);
    
    // Populate providers
    populateComponentList('providersList', components.providers);
}

/**
 * Populate a component list
 */
function populateComponentList(listId, items) {
    const list = document.getElementById(listId);
    if (!list) return;
    
    // Clear existing content
    list.innerHTML = '';
    
    if (!items || items.length === 0) {
        list.innerHTML = '<p class="text-center">No components found</p>';
        return;
    }
    
    // Create table
    const table = document.createElement('table');
    table.className = 'cyber-table';
    
    // Add header row
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    
    const nameHeader = document.createElement('th');
    nameHeader.textContent = 'Component Name';
    headerRow.appendChild(nameHeader);
    
    const descHeader = document.createElement('th');
    descHeader.textContent = 'Description';
    headerRow.appendChild(descHeader);
    
    const exportedHeader = document.createElement('th');
    exportedHeader.textContent = 'Exported';
    headerRow.appendChild(exportedHeader);
    
    thead.appendChild(headerRow);
    table.appendChild(thead);
    
    // Add body
    const tbody = document.createElement('tbody');
    
    items.forEach(item => {
        const row = document.createElement('tr');
        
        // Name
        const nameCell = document.createElement('td');
        nameCell.textContent = item.name || 'Unknown';
        row.appendChild(nameCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = item.description || 'No description available';
        row.appendChild(descCell);
        
        // Exported
        const exportedCell = document.createElement('td');
        if (item.exported === true) {
            exportedCell.innerHTML = '<i class="fas fa-check text-success"></i>';
        } else if (item.exported === false) {
            exportedCell.innerHTML = '<i class="fas fa-times text-danger"></i>';
        } else {
            exportedCell.textContent = 'Unknown';
        }
        row.appendChild(exportedCell);
        
        tbody.appendChild(row);
    });
    
    table.appendChild(tbody);
    list.appendChild(table);
}

/**
 * Populate network traffic section
 */
function populateNetworkTraffic(traffic) {
    const networkTableBody = document.getElementById('networkTableBody');
    if (!networkTableBody) return;
    
    // Clear existing content
    networkTableBody.innerHTML = '';
    
    if (!traffic || traffic.length === 0) {
        networkTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No network traffic detected</td></tr>';
        return;
    }
    
    // Sort by risk level (high to low)
    const sortedTraffic = [...traffic].sort((a, b) => {
        const riskOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'safe': 0 };
        return (riskOrder[b.risk_level] || 0) - (riskOrder[a.risk_level] || 0);
    });
    
    // Add each traffic item to the table
    sortedTraffic.forEach(item => {
        const row = document.createElement('tr');
        
        // Destination
        const destCell = document.createElement('td');
        destCell.textContent = item.destination || 'Unknown';
        row.appendChild(destCell);
        
        // Protocol
        const protoCell = document.createElement('td');
        protoCell.textContent = item.protocol || 'Unknown';
        row.appendChild(protoCell);
        
        // Port
        const portCell = document.createElement('td');
        portCell.textContent = item.port || 'Unknown';
        row.appendChild(portCell);
        
        // Status
        const statusCell = document.createElement('td');
        statusCell.textContent = item.status || 'Unknown';
        row.appendChild(statusCell);
        
        // Risk level
        const riskCell = document.createElement('td');
        const riskSpan = document.createElement('span');
        riskSpan.className = `risk-badge risk-${item.risk_level || 'unknown'}`;
        riskSpan.textContent = item.risk_level ? capitalizeFirst(item.risk_level) : 'Unknown';
        riskCell.appendChild(riskSpan);
        row.appendChild(riskCell);
        
        networkTableBody.appendChild(row);
    });
}

/**
 * Populate file operations section
 */
function populateFileOperations(operations) {
    const fileOpsTableBody = document.getElementById('fileOpsTableBody');
    if (!fileOpsTableBody) return;
    
    // Clear existing content
    fileOpsTableBody.innerHTML = '';
    
    if (!operations || operations.length === 0) {
        fileOpsTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No file operations detected</td></tr>';
        return;
    }
    
    // Sort by risk level (high to low)
    const sortedOps = [...operations].sort((a, b) => {
        const riskOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'safe': 0 };
        return (riskOrder[b.risk_level] || 0) - (riskOrder[a.risk_level] || 0);
    });
    
    // Add each operation to the table
    sortedOps.forEach(op => {
        const row = document.createElement('tr');
        
        // Operation
        const opCell = document.createElement('td');
        opCell.textContent = op.operation || 'Unknown';
        row.appendChild(opCell);
        
        // Path
        const pathCell = document.createElement('td');
        pathCell.textContent = op.path || 'Unknown';
        row.appendChild(pathCell);
        
        // Risk level
        const riskCell = document.createElement('td');
        const riskSpan = document.createElement('span');
        riskSpan.className = `risk-badge risk-${op.risk_level || 'unknown'}`;
        riskSpan.textContent = op.risk_level ? capitalizeFirst(op.risk_level) : 'Unknown';
        riskCell.appendChild(riskSpan);
        row.appendChild(riskCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = op.description || 'No description available';
        row.appendChild(descCell);
        
        fileOpsTableBody.appendChild(row);
    });
}

/**
 * Populate suspicious behaviors section
 */
function populateBehaviors(behaviors) {
    const behaviorsTableBody = document.getElementById('behaviorsTableBody');
    if (!behaviorsTableBody) return;
    
    // Clear existing content
    behaviorsTableBody.innerHTML = '';
    
    if (!behaviors || behaviors.length === 0) {
        behaviorsTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No suspicious behaviors detected</td></tr>';
        return;
    }
    
    // Sort by risk level (high to low)
    const sortedBehaviors = [...behaviors].sort((a, b) => {
        const riskOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'safe': 0 };
        return (riskOrder[b.risk_level] || 0) - (riskOrder[a.risk_level] || 0);
    });
    
    // Add each behavior to the table
    sortedBehaviors.forEach(behavior => {
        const row = document.createElement('tr');
        
        // Behavior type
        const typeCell = document.createElement('td');
        typeCell.textContent = behavior.type || 'Unknown';
        row.appendChild(typeCell);
        
        // Risk level
        const riskCell = document.createElement('td');
        const riskSpan = document.createElement('span');
        riskSpan.className = `risk-badge risk-${behavior.risk_level || 'unknown'}`;
        riskSpan.textContent = behavior.risk_level ? capitalizeFirst(behavior.risk_level) : 'Unknown';
        riskCell.appendChild(riskSpan);
        row.appendChild(riskCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = behavior.description || 'No description available';
        row.appendChild(descCell);
        
        // Action
        const actionCell = document.createElement('td');
        if (behavior.action) {
            const actionBtn = document.createElement('button');
            actionBtn.className = 'cyber-button cyber-button-small';
            actionBtn.textContent = 'Details';
            actionCell.appendChild(actionBtn);
        } else {
            actionCell.textContent = 'No action available';
        }
        row.appendChild(actionCell);
        
        behaviorsTableBody.appendChild(row);
    });
}

/**
 * Populate vulnerabilities section
 */
function populateVulnerabilities(vulnerabilities) {
    const vulnerabilitiesTableBody = document.getElementById('vulnerabilitiesTableBody');
    if (!vulnerabilitiesTableBody) return;
    
    // Clear existing content
    vulnerabilitiesTableBody.innerHTML = '';
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        vulnerabilitiesTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No vulnerabilities detected</td></tr>';
        return;
    }
    
    // Sort by severity (high to low)
    const sortedVulns = [...vulnerabilities].sort((a, b) => {
        const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0 };
        return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    });
    
    // Add each vulnerability to the table
    sortedVulns.forEach(vuln => {
        const row = document.createElement('tr');
        
        // Vulnerability name
        const nameCell = document.createElement('td');
        nameCell.textContent = vuln.name || 'Unknown';
        row.appendChild(nameCell);
        
        // Severity
        const sevCell = document.createElement('td');
        const sevSpan = document.createElement('span');
        sevSpan.className = `risk-badge risk-${vuln.severity || 'unknown'}`;
        sevSpan.textContent = vuln.severity ? capitalizeFirst(vuln.severity) : 'Unknown';
        sevCell.appendChild(sevSpan);
        row.appendChild(sevCell);
        
        // CVE
        const cveCell = document.createElement('td');
        if (vuln.cve) {
            const cveLink = document.createElement('a');
            cveLink.href = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}`;
            cveLink.target = '_blank';
            cveLink.textContent = vuln.cve;
            cveLink.className = 'cyber-link';
            cveCell.appendChild(cveLink);
        } else {
            cveCell.textContent = 'N/A';
        }
        row.appendChild(cveCell);
        
        // Description
        const descCell = document.createElement('td');
        descCell.textContent = vuln.description || 'No description available';
        row.appendChild(descCell);
        
        // Recommendation
        const recCell = document.createElement('td');
        recCell.textContent = vuln.recommendation || 'No recommendation available';
        row.appendChild(recCell);
        
        vulnerabilitiesTableBody.appendChild(row);
    });
}

/**
 * Helper function to capitalize first letter
 */
function capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// CSS for risk badges (appended to styles already in main CSS)
document.addEventListener('DOMContentLoaded', function() {
    const style = document.createElement('style');
    style.textContent = `
        /* Risk badges */
        .risk-badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .risk-critical {
            background-color: rgba(220, 53, 69, 0.2);
            color: #dc3545;
            border: 1px solid rgba(220, 53, 69, 0.3);
        }
        
        .risk-high {
            background-color: rgba(253, 126, 20, 0.2);
            color: #fd7e14;
            border: 1px solid rgba(253, 126, 20, 0.3);
        }
        
        .risk-medium {
            background-color: rgba(255, 193, 7, 0.2);
            color: #ffc107;
            border: 1px solid rgba(255, 193, 7, 0.3);
        }
        
        .risk-low {
            background-color: rgba(64, 203, 217, 0.2);
            color: #40cbd9;
            border: 1px solid rgba(64, 203, 217, 0.3);
        }
        
        .risk-safe {
            background-color: rgba(40, 167, 69, 0.2);
            color: #28a745;
            border: 1px solid rgba(40, 167, 69, 0.3);
        }
        
        .risk-info {
            background-color: rgba(23, 162, 184, 0.2);
            color: #17a2b8;
            border: 1px solid rgba(23, 162, 184, 0.3);
        }
        
        .risk-unknown {
            background-color: rgba(108, 117, 125, 0.2);
            color: #6c757d;
            border: 1px solid rgba(108, 117, 125, 0.3);
        }
        
        /* Small button variant */
        .cyber-button-small {
            padding: 0.2rem 0.5rem;
            font-size: 0.75rem;
        }
        
        /* Link styling */
        .cyber-link {
            color: var(--cyber-accent-primary);
            text-decoration: none;
            transition: all 0.2s ease;
        }
        
        .cyber-link:hover {
            color: var(--cyber-accent-secondary);
            text-decoration: underline;
        }
    `;
    document.head.appendChild(style);
});

/**
 * APK Malware Scanner - Main JavaScript
 * Handles file upload interactions and UI updates
 */

document.addEventListener('DOMContentLoaded', function() {
    // Elements for file upload
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    
    // Elements for progress and status indicators
    const uploadStatus = document.getElementById('uploadStatus');
    const fileNameLabel = document.getElementById('fileNameLabel');
    const uploadProgressBar = document.getElementById('uploadProgressBar');
    const uploadStatusText = document.getElementById('uploadStatusText');
    
    // Elements for analysis progress
    const analysisStatus = document.getElementById('analysisStatus');
    const analysisFileNameLabel = document.getElementById('analysisFileNameLabel');
    const analysisStatusText = document.getElementById('analysisStatusText');
    
    // Error modal
    const errorModal = new bootstrap.Modal(document.getElementById('errorModal'));
    const errorModalText = document.getElementById('errorModalText');
    
    // Only initialize if on the upload page
    if (dropZone && fileInput) {
        initializeFileUpload();
    }
    
    // Set up collapsible sections
    setupCollapsibles();
    
    /**
     * Initialize file upload functionality
     * Handles drag and drop plus manual file selection
     */
    function initializeFileUpload() {
        // Handle file selection via dialog
        fileInput.addEventListener('change', function() {
            if (fileInput.files.length > 0) {
                handleFiles(fileInput.files);
            }
        });
        
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        // Highlight drop zone when dragging over it
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });
        
        // Handle dropped files
        dropZone.addEventListener('drop', handleDrop, false);
        
        // Handle click on drop zone
        dropZone.addEventListener('click', function() {
            fileInput.click();
        });
    }
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    function highlight() {
        dropZone.classList.add('drag-over');
    }
    
    function unhighlight() {
        dropZone.classList.remove('drag-over');
    }
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    }
    
    /**
     * Process the selected files
     * @param {FileList} files - The files selected by the user
     */
    function handleFiles(files) {
        if (files.length === 0) return;
        
        const file = files[0];
        
        // Check if it's an APK file
        if (!file.name.toLowerCase().endsWith('.apk')) {
            showError('Invalid file format. Only APK files are allowed.');
            return;
        }
        
        // Check file size (max 50MB)
        if (file.size > 50 * 1024 * 1024) {
            showError('File too large. Maximum size is 50MB.');
            return;
        }
        
        // Show upload status
        fileNameLabel.textContent = file.name;
        uploadStatus.classList.remove('d-none');
        uploadProgressBar.style.width = '0%';
        uploadStatusText.textContent = 'Preparing upload...';
        
        // Upload the file
        uploadFile(file);
    }
    
    /**
     * Upload the file to the server
     * @param {File} file - The file to upload
     */
    function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        const xhr = new XMLHttpRequest();
        
        // Progress event
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                uploadProgressBar.style.width = percentComplete + '%';
                uploadStatusText.textContent = `Uploading: ${percentComplete}%`;
            }
        });
        
        // Upload complete
        xhr.addEventListener('load', function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                uploadStatusText.textContent = 'Upload complete!';
                const response = JSON.parse(xhr.responseText);
                
                if (response.success) {
                    // Show analysis status
                    if (analysisStatus) {
                        uploadStatus.classList.add('d-none');
                        analysisStatus.classList.remove('d-none');
                        analysisFileNameLabel.textContent = file.name;
                        analysisStatusText.textContent = 'Starting analysis...';
                        
                        // If there's a redirect URL, go there
                        if (response.redirect) {
                            simulateAnalysisProgress(response.redirect);
                        }
                    } else {
                        window.location.href = response.redirect;
                    }
                } else if (response.error) {
                    showError(response.error);
                }
            } else {
                try {
                    const response = JSON.parse(xhr.responseText);
                    showError(response.error || 'Upload failed');
                } catch (e) {
                    showError('Upload failed. Please try again.');
                }
            }
        });
        
        // Error handling
        xhr.addEventListener('error', function() {
            showError('Network error occurred. Please try again.');
        });
        
        // Abort handling
        xhr.addEventListener('abort', function() {
            showError('Upload aborted.');
        });
        
        // Send the file
        xhr.open('POST', '/upload', true);
        xhr.send(formData);
    }
    
    /**
     * Simulate analysis progress and then redirect
     * @param {string} redirectUrl - URL to redirect to after "analysis"
     */
    function simulateAnalysisProgress(redirectUrl) {
        // Simulating analysis status updates for better UX
        const statusMessages = [
            'Performing static analysis...',
            'Checking code patterns...',
            'Analyzing permissions...',
            'Scanning for vulnerabilities...',
            'Performing dynamic analysis...',
            'Analyzing network behavior...',
            'Generating report...',
            'Analysis complete!'
        ];
        
        let currentStep = 0;
        
        // Update status message every 800ms
        const statusInterval = setInterval(() => {
            if (currentStep < statusMessages.length) {
                analysisStatusText.textContent = statusMessages[currentStep];
                currentStep++;
            } else {
                clearInterval(statusInterval);
                window.location.href = redirectUrl;
            }
        }, 800);
    }
    
    /**
     * Show error message in modal
     * @param {string} message - Error message to display
     */
    function showError(message) {
        errorModalText.textContent = message;
        errorModal.show();
        
        // Reset UI
        if (uploadStatus) {
            uploadStatus.classList.add('d-none');
        }
        if (analysisStatus) {
            analysisStatus.classList.add('d-none');
        }
    }
    
    /**
     * Setup collapsible sections
     */
    function setupCollapsibles() {
        const collapsibles = document.querySelectorAll('.collapsible');
        
        collapsibles.forEach(collapsible => {
            collapsible.addEventListener('click', function() {
                const target = document.querySelector(this.getAttribute('data-bs-target'));
                
                // Toggle the collapse state
                if (this.getAttribute('aria-expanded') === 'true') {
                    this.setAttribute('aria-expanded', 'false');
                    target.classList.remove('show');
                } else {
                    this.setAttribute('aria-expanded', 'true');
                    target.classList.add('show');
                }
            });
            
            // Initialize aria-expanded attribute
            const targetId = collapsible.getAttribute('data-bs-target');
            const target = document.querySelector(targetId);
            
            if (target && target.classList.contains('show')) {
                collapsible.setAttribute('aria-expanded', 'true');
            } else {
                collapsible.setAttribute('aria-expanded', 'false');
            }
        });
    }
});

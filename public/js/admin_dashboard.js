// public/admin_dashboard.js

// Global array to store tracking data, fetched from the API
let trackings = [];
let userRole = localStorage.getItem('userRole'); // Get user role from local storage

// --- Utility Functions ---

function logout() {
    localStorage.removeItem('adminToken');
    localStorage.removeItem('userRole');
    window.location.href = '/admin_login.html';
}

function isAuthenticated() {
    const token = localStorage.getItem('adminToken');
    // Basic check: token exists. More robust check would involve verifying token validity with backend.
    return !!token;
}

function hasAdminPrivileges() {
    return userRole === 'admin';
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    } catch (e) {
        console.error('Error formatting date:', e, dateString);
        return dateString;
    }
}

function formatTime(timeString) {
    if (!timeString) return 'N/A';
    try {
        // Assuming timeString is like "HH:MM"
        const [hours, minutes] = timeString.split(':');
        const date = new Date();
        date.setHours(parseInt(hours, 10), parseInt(minutes, 10), 0);
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    } catch (e) {
        console.error('Error formatting time:', e, timeString);
        return timeString;
    }
}

// Helper function to update status circle based on input value
function updateStatusIndicator(statusInputId, statusCircleId, isBlinkingCheckboxId) {
    const statusInput = document.getElementById(statusInputId);
    const statusCircle = document.getElementById(statusCircleId);
    const isBlinkingCheckbox = document.getElementById(isBlinkingCheckboxId);

    if (!statusInput || !statusCircle) return;

    function applyStatusStyles() {
        const status = statusInput.value.toLowerCase();
        statusCircle.className = 'status-circle'; // Reset classes

        if (status.includes('delivered')) {
            statusCircle.classList.add('delivered');
        } else if (status.includes('in-transit') || status.includes('transit')) {
            statusCircle.classList.add('in-transit');
        } else if (status.includes('pending') || status.includes('hold')) {
            statusCircle.classList.add('pending');
        } else if (status.includes('exception') || status.includes('failed')) {
            statusCircle.classList.add('exception');
        } else {
            statusCircle.classList.add('unknown'); // Default for unrecognized status
        }

        if (isBlinkingCheckbox && isBlinkingCheckbox.checked) {
            statusCircle.classList.add('blinking');
        }
    }

    statusInput.addEventListener('input', applyStatusStyles);
    if (isBlinkingCheckbox) {
        isBlinkingCheckbox.addEventListener('change', applyStatusStyles);
    }
    applyStatusStyles(); // Apply on load
}


// --- API Calls ---

async function fetchAllTrackings() {
    try {
        const response = await fetch('/api/admin/trackings', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                alert('Session expired or unauthorized. Please log in again.');
                logout();
                return [];
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        trackings = data; // Update the global trackings array
        return data;
    } catch (error) {
        console.error('Error fetching trackings:', error);
        alert('Failed to load tracking data. Please try again.');
        return [];
    }
}

async function fetchDashboardStats() {
    try {
        const response = await fetch('/api/admin/dashboard-stats', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        return {
            total: 0,
            delivered: 0,
            inTransit: 0,
            pending: 0,
            exceptions: 0
        };
    }
}

async function fetchSingleTracking(trackingMongoId) {
    try {
        const response = await fetch(`/api/admin/trackings/${trackingMongoId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching single tracking:', error);
        alert('Failed to load tracking details.');
        return null;
    }
}

async function addTracking(trackingData) {
    try {
        const response = await fetch('/api/admin/trackings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify(trackingData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to add tracking. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error adding tracking:', error);
        alert(`Error adding new tracking: ${error.message}`);
        throw error; // Re-throw to allow calling function to handle
    }
}

async function updateTracking(mongoId, updatedData) {
    try {
        const response = await fetch(`/api/admin/trackings/${mongoId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify(updatedData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to update tracking. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error updating tracking:', error);
        alert(`Error updating tracking: ${error.message}`);
        throw error;
    }
}

async function deleteTracking(mongoId) {
    try {
        const response = await fetch(`/api/admin/trackings/${mongoId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to delete tracking. Status: ${response.status}`);
        }
        return true; // Indicate success
    } catch (error) {
        console.error('Error deleting tracking:', error);
        alert(`Error deleting tracking: ${error.message}`);
        throw error;
    }
}

async function addHistoryEvent(trackingMongoId, historyData) {
    try {
        const response = await fetch(`/api/admin/trackings/${trackingMongoId}/history`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify(historyData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to add history event. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error adding history event:', error);
        alert(`Error adding history event: ${error.message}`);
        throw error;
    }
}

async function updateHistoryEvent(trackingMongoId, historyId, updatedData) {
    try {
        const response = await fetch(`/api/admin/trackings/${trackingMongoId}/history/${historyId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify(updatedData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to update history event. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error updating history event:', error);
        alert(`Error updating history event: ${error.message}`);
        throw error;
    }
}

async function deleteHistoryEvent(trackingMongoId, historyId) {
    try {
        const response = await fetch(`/api/admin/trackings/${trackingMongoId}/history/${historyId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to delete history event. Status: ${response.status}`);
        }
        return true; // Indicate success
    } catch (error) {
        console.error('Error deleting history event:', error);
        alert(`Error deleting history event: ${error.message}`);
        throw error;
    }
}

async function sendEmail(formData) {
    try {
        const response = await fetch('/api/admin/send-email', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to send email. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error sending email:', error);
        alert(`Error sending email: ${error.message}`);
        throw error;
    }
}

async function uploadFile(formData) {
    try {
        const response = await fetch('/api/admin/upload-package-file', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `Failed to upload file. Status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error uploading file:', error);
        alert(`Error uploading file: ${error.message}`);
        throw error;
    }
}

// --- DOM Element Declarations (inside DOMContentLoaded for safety, or globally if needed across modules) ---
// For this single file structure, declaring them once inside DOMContentLoaded is fine.

// --- Dashboard Rendering Functions ---

async function updateDashboardStats() {
    const stats = await fetchDashboardStats();
    if (stats) {
        document.getElementById('totalPackages').textContent = stats.total;
        document.getElementById('deliveredPackages').textContent = stats.delivered;
        document.getElementById('inTransitPackages').textContent = stats.inTransit;
        document.getElementById('pendingPackages').textContent = stats.pending;
        document.getElementById('exceptionsPackages').textContent = stats.exceptions;
    }
}

function renderAllTrackingsTable() {
    const allTrackingsTableBody = document.getElementById('all-trackings-table-body');
    if (!allTrackingsTableBody) return;

    allTrackingsTableBody.innerHTML = ''; // Clear existing rows

    if (trackings.length === 0) {
        allTrackingsTableBody.innerHTML = '<tr><td colspan="13" style="text-align: center; padding: 20px;">No tracking data available.</td></tr>';
        return;
    }

    trackings.forEach(tracking => {
        const row = allTrackingsTableBody.insertRow();
        row.insertCell().textContent = tracking.trackingId;
        row.insertCell().textContent = tracking.status;

        const statusColorCell = row.insertCell();
        const statusColorDiv = document.createElement('div');
        statusColorDiv.style.width = '20px';
        statusColorDiv.style.height = '20px';
        statusColorDiv.style.borderRadius = '50%';
        statusColorDiv.style.backgroundColor = tracking.statusLineColor || '#2196F3'; // Default blue if not set
        statusColorDiv.style.border = '1px solid #ccc';
        statusColorCell.appendChild(statusColorDiv);

        const blinkingCell = row.insertCell();
        const blinkingIcon = document.createElement('i');
        blinkingIcon.classList.add('fas');
        blinkingIcon.classList.add(tracking.isBlinking ? 'fa-check-circle' : 'fa-times-circle');
        blinkingIcon.style.color = tracking.isBlinking ? 'var(--success-green)' : 'var(--danger-red)';
        blinkingCell.appendChild(blinkingIcon);

        row.insertCell().textContent = tracking.senderName || 'N/A';
        row.insertCell().textContent = tracking.recipientName || 'N/A';
        row.insertCell().textContent = tracking.packageContents || 'N/A';
        row.insertCell().textContent = tracking.serviceType || 'N/A';
        row.insertCell().textContent = tracking.recipientAddress || 'N/A';
        row.insertCell().textContent = tracking.specialHandling || 'N/A';
        row.insertCell().textContent = `${formatDate(tracking.expectedDeliveryDate)} ${formatTime(tracking.expectedDeliveryTime)}`;
        row.insertCell().textContent = tracking.lastUpdated ? new Date(tracking.lastUpdated).toLocaleString() : 'N/A';

        const actionsCell = row.insertCell();
        const viewEditButton = document.createElement('button');
        viewEditButton.textContent = 'View/Edit';
        viewEditButton.classList.add('btn', 'btn-info', 'btn-small', 'mr-2');
        viewEditButton.dataset.mongoId = tracking._id; // Store Mongo ID for easy access
        actionsCell.appendChild(viewEditButton);

        const deleteButton = document.createElement('button');
        deleteButton.textContent = 'Delete';
        deleteButton.classList.add('btn', 'btn-danger', 'btn-small');
        deleteButton.dataset.mongoId = tracking._id; // Store Mongo ID for easy access
        actionsCell.appendChild(deleteButton);
    });
    attachTableButtonListeners(); // Attach listeners after rendering
}

function renderTrackingHistory(trackingHistory, trackingMongoId) {
    const trackingHistoryList = document.getElementById('trackingHistoryList');
    if (!trackingHistoryList) return;

    const ul = trackingHistoryList.querySelector('ul');
    ul.innerHTML = ''; // Clear previous history

    if (trackingHistory && trackingHistory.length > 0) {
        // Sort history by date and time
        trackingHistory.sort((a, b) => {
            const dateA = new Date(`${a.date} ${a.time}`);
            const dateB = new Date(`${b.date} ${b.time}`);
            return dateA - dateB;
        });

        trackingHistory.forEach(event => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div class="history-content">
                    <strong>${formatDate(event.date)} ${formatTime(event.time)}:</strong> ${event.location || 'N/A'} - ${event.description || 'N/A'}
                </div>
                <div class="history-actions">
                    <button class="btn btn-info btn-small edit-history-btn" data-history-id="${event.id}" data-tracking-mongo-id="${trackingMongoId}">Edit</button>
                    <button class="btn btn-danger btn-small delete-history-btn" data-history-id="${event.id}" data-tracking-mongo-id="${trackingMongoId}">Delete</button>
                </div>
            `;
            ul.appendChild(li);
        });
    } else {
        ul.innerHTML = '<li>No history entries yet.</li>';
    }
}

// --- Event Listener Attachment Functions ---

function attachTableButtonListeners() {
    const allTrackingsTableBody = document.getElementById('all-trackings-table-body');
    if (!allTrackingsTableBody) return;

    allTrackingsTableBody.addEventListener('click', async function(event) {
        const target = event.target;
        const mongoId = target.dataset.mongoId;

        if (!mongoId) return; // Not a button with a mongoId

        if (target.classList.contains('btn-info')) { // View/Edit button
            loadTrackingForEdit(mongoId);
            // Switch to "Manage Single Tracking" section
            document.querySelectorAll('.sidebar ul li a').forEach(link => link.classList.remove('active'));
            const manageLink = document.querySelector('[data-section="manage-tracking-section"]');
            if (manageLink) manageLink.classList.add('active');
            document.querySelectorAll('.dashboard-section').forEach(section => section.classList.remove('active-section'));
            document.getElementById('manage-tracking-section').classList.add('active-section');
        } else if (target.classList.contains('btn-danger')) { // Delete button
            if (confirm(`Are you sure you want to delete this tracking entry?`)) {
                try {
                    await deleteTracking(mongoId);
                    alert('Tracking Deleted Successfully!');
                    initializeDashboard(); // Re-fetch all data and re-render
                    // Hide update form and history if the deleted item was currently displayed
                    const updateTrackingForm = document.getElementById('updateTrackingForm');
                    if (updateTrackingForm && document.getElementById('updateTrackingMongoId').value === mongoId) {
                        updateTrackingForm.style.display = 'none';
                        document.getElementById('trackingHistoryList').querySelector('ul').innerHTML = '<li>No history entries yet.</li>';
                    }
                } catch (error) {
                    // Error handled in deleteTracking
                }
            }
        }
    });
}

function attachHistoryButtonListeners() {
    const trackingHistoryList = document.getElementById('trackingHistoryList');
    if (!trackingHistoryList) return;

    trackingHistoryList.addEventListener('click', async function(event) {
        const target = event.target;
        const historyId = parseInt(target.dataset.historyId);
        const trackingMongoId = target.dataset.trackingMongoId;

        if (!historyId || !trackingMongoId) return;

        if (target.classList.contains('edit-history-btn')) {
            const tracking = trackings.find(t => t._id === trackingMongoId);
            const historyEvent = tracking ? tracking.history.find(h => h.id === historyId) : null;

            if (historyEvent) {
                document.getElementById('editHistoryModalTrackingMongoId').value = trackingMongoId; // Set Mongo ID
                document.getElementById('editHistoryModalHistoryId').value = historyId;
                document.getElementById('editHistoryDate').value = historyEvent.date;
                document.getElementById('editHistoryTime').value = historyEvent.time;
                document.getElementById('editHistoryLocation').value = historyEvent.location;
                document.getElementById('editHistoryDescription').value = historyEvent.description;

                const editHistoryModal = document.getElementById('editHistoryModal');
                const instance = M.Modal.getInstance(editHistoryModal);
                if (instance) instance.open();
                M.updateTextFields();
            } else {
                alert('History event not found.');
            }
        } else if (target.classList.contains('delete-history-btn')) {
            if (confirm('Are you sure you want to delete this history event?')) {
                try {
                    await deleteHistoryEvent(trackingMongoId, historyId);
                    alert('History event deleted!');
                    // Re-load tracking details to refresh history from backend
                    loadTrackingForEdit(trackingMongoId);
                    initializeDashboard(); // Refresh overall table for last updated date etc.
                } catch (error) {
                    // Error handled in deleteHistoryEvent
                }
            }
        }
    });
}


// --- Form Submission Handlers ---

async function handleAddTrackingForm(event) {
    event.preventDefault();

    const newTrackingData = {
        trackingId: document.getElementById('addTrackingId').value,
        status: document.getElementById('addStatus').value,
        description: document.getElementById('addDescription').value,
        isBlinking: document.getElementById('addIsBlinking').checked,
        statusLineColor: document.getElementById('addStatusLineColor').value,
        blinkingDotColor: document.getElementById('addBlinkingDotColor').value,
        senderName: document.getElementById('addSenderName').value,
        recipientName: document.getElementById('addRecipientName').value,
        recipientEmail: document.getElementById('addRecipientEmail').value,
        packageContents: document.getElementById('addPackageContents').value,
        serviceType: document.getElementById('addServiceType').value,
        recipientAddress: document.getElementById('addRecipientAddress').value,
        specialHandling: document.getElementById('addSpecialHandling').value,
        expectedDeliveryDate: document.getElementById('addExpectedDeliveryDate').value,
        expectedDeliveryTime: document.getElementById('addExpectedDeliveryTime').value,
        origin: document.getElementById('addOrigin').value,
        destination: document.getElementById('addDestination').value,
        weight: parseFloat(document.getElementById('addWeight').value),
        history: [] // New trackings start with empty history, added separately
    };

    try {
        await addTracking(newTrackingData);
        alert('New Tracking Added Successfully!');
        document.getElementById('addTrackingForm').reset();
        initializeDashboard(); // Re-fetch all data and re-render dashboard
    } catch (error) {
        // Error already alerted in addTracking
    }
}

async function handleUpdateTrackingForm(event) {
    event.preventDefault();

    const mongoId = document.getElementById('updateTrackingMongoId').value;
    if (!mongoId) {
        alert('No tracking selected for update.');
        return;
    }

    const updatedTrackingData = {
        trackingId: document.getElementById('updateTrackingId').value,
        status: document.getElementById('updateStatus').value,
        description: document.getElementById('updateDescription').value,
        isBlinking: document.getElementById('updateIsBlinkingOriginal').checked,        
        statusLineColor: document.getElementById('updateStatusLineColor').value,
        blinkingDotColor: document.getElementById('updateBlinkingDotColor').value,
        senderName: document.getElementById('updateSenderName').value,
        recipientName: document.getElementById('updateRecipientName').value,
       // recipientEmail: document.getElementById('updateRecipientEmail').value,
        packageContents: document.getElementById('updatePackageContents').value,
        serviceType: document.getElementById('updateServiceType').value,
        recipientAddress: document.getElementById('updateRecipientAddress').value,
        specialHandling: document.getElementById('updateSpecialHandling').value,
        expectedDeliveryDate: document.getElementById('updateExpectedDeliveryDate').value,
        expectedDeliveryTime: document.getElementById('updateExpectedDeliveryTime').value,
        origin: document.getElementById('updateOrigin').value,
        destination: document.getElementById('updateDestination').value,
        weight: parseFloat(document.getElementById('updateWeight').value),
        lastUpdated: new Date().toISOString() // Update timestamp
    };

    try {
        await updateTracking(mongoId, updatedTrackingData);
        alert('Tracking Updated Successfully!');
        initializeDashboard(); // Re-fetch all data and re-render dashboard
        loadTrackingForEdit(mongoId); // Re-load the specific tracking to update its form fields
    } catch (error) {
        // Error already alerted in updateTracking
    }
}

async function handleAddHistoryForm(event) {
    event.preventDefault();
    const trackingMongoId = document.getElementById('updateTrackingMongoId').value; // Get the currently selected tracking's mongoId

    if (!trackingMongoId) {
        alert('Please select a tracking ID first in the "Manage Single Tracking" section.');
        return;
    }

    const newHistoryEventData = {
        date: document.getElementById('newHistoryDate').value,
        time: document.getElementById('newHistoryTime').value,
        location: document.getElementById('newHistoryLocation').value,
        description: document.getElementById('newHistoryDescription').value
    };

    try {
        await addHistoryEvent(trackingMongoId, newHistoryEventData);
        alert('New History Event Added!');
        document.getElementById('addHistoryForm').reset();
        loadTrackingForEdit(trackingMongoId); // Re-fetch and render history for the current tracking
        initializeDashboard(); // Update main table for last updated
    } catch (error) {
        // Error already alerted in addHistoryEvent
    }
}

async function handleSaveHistoryEdit(event) {
    event.preventDefault();
    const trackingMongoId = document.getElementById('editHistoryModalTrackingMongoId').value;
    const historyId = parseInt(document.getElementById('editHistoryModalHistoryId').value);

    if (!trackingMongoId || isNaN(historyId)) {
        alert('Error: Missing tracking or history ID for update.');
        return;
    }

    const updatedHistoryData = {
        date: document.getElementById('editHistoryDate').value,
        time: document.getElementById('editHistoryTime').value,
        location: document.getElementById('editHistoryLocation').value,
        description: document.getElementById('editHistoryDescription').value
    };

    try {
        await updateHistoryEvent(trackingMongoId, historyId, updatedHistoryData);
        alert('History event updated!');
        const editHistoryModal = document.getElementById('editHistoryModal');
        M.Modal.getInstance(editHistoryModal).close();
        loadTrackingForEdit(trackingMongoId); // Re-fetch and render history for the current tracking
        initializeDashboard(); // Update main table for last updated
    } catch (error) {
        // Error already alerted in updateHistoryEvent
    }
}


async function handleSendEmailForm(event) {
    event.preventDefault();
    const recipientEmail = document.getElementById('notificationEmail').value;
    const subject = document.getElementById('emailSubject').value;
    const message = document.getElementById('notificationMessage').value;
    const emailAttachmentFile = document.getElementById('emailAttachmentFileUpload').files[0];
    const trackingIdForEmail = document.getElementById('emailTrackingIdSelect').value; // Ensure this is the correct ID for the select

    if (!recipientEmail || !subject || !message) {
        alert('Please fill in all email fields: Recipient, Subject, and Message.');
        return;
    }

    const formData = new FormData();
    formData.append('to', recipientEmail);
    formData.append('subject', subject);
    formData.append('body', message);
    if (trackingIdForEmail) { // Only append if a tracking ID was selected
        formData.append('trackingId', trackingIdForEmail);
    }

    if (emailAttachmentFile) {
        formData.append('attachment', emailAttachmentFile);
    }

    try {
        await sendEmail(formData);
        alert(`Email to ${recipientEmail} with subject "${subject}" sent successfully!`);
        document.getElementById('sendEmailForm').reset();
        const filePathInput = document.getElementById('emailAttachmentFileUpload').closest('.file-field').querySelector('.file-path');
        if (filePathInput) filePathInput.value = '';
        M.FormSelect.init(document.getElementById('emailTrackingIdSelect')); // Re-init to clear display
    } catch (error) {
        // Error already alerted in sendEmail
    }
}

async function handleUploadPackageFileForm(event) {
    event.preventDefault();
    const fileTrackingId = document.getElementById('attachFileTrackingIdSelect').value;
    const packageFile = document.getElementById('packageFileInput').files[0];

    if (!fileTrackingId) {
        alert('Please select a tracking ID for the file upload.');
        return;
    }
    if (!packageFile) {
        alert('Please select a file to upload.');
        return;
    }

    const formData = new FormData();
    formData.append('trackingId', fileTrackingId);
    formData.append('packageFile', packageFile);

    try {
        await uploadFile(formData);
        alert(`File "${packageFile.name}" uploaded and linked to ${fileTrackingId} successfully!`);
        document.getElementById('uploadPackageFileForm').reset();
        const filePathInput = document.getElementById('packageFileInput').closest('.file-field').querySelector('.file-path');
        if (filePathInput) filePathInput.value = '';
        M.FormSelect.init(document.getElementById('attachFileTrackingIdSelect')); // Re-init to clear display
    } catch (error) {
        // Error already alerted in uploadFile
    }
}

// --- Dynamic Form Population (for single tracking view) ---
async function loadTrackingForEdit(mongoId) {
    const tracking = await fetchSingleTracking(mongoId);
    const updateTrackingForm = document.getElementById('updateTrackingForm');
    if (!updateTrackingForm) return;

    if (tracking) {
        updateTrackingForm.style.display = 'block';
        document.getElementById('updateTrackingMongoId').value = tracking._id;
        document.getElementById('updateTrackingId').value = tracking.trackingId || '';
        document.getElementById('updateStatus').value = tracking.status || '';
        document.getElementById('updateDescription').value = tracking.description || '';
    document.getElementById('updateIsBlinkingOriginal').checked = tracking.isBlinking || false;        document.getElementById('updateStatusLineColor').value = tracking.statusLineColor || '#2196F3';
        document.getElementById('updateBlinkingDotColor').value = tracking.blinkingDotColor || '#FFFFFF';
        document.getElementById('updateSenderName').value = tracking.senderName || '';
        document.getElementById('updateRecipientName').value = tracking.recipientName || '';
       // document.getElementById('updateRecipientEmail').value = tracking.recipientEmail || '';
        document.getElementById('updatePackageContents').value = tracking.packageContents || '';
        document.getElementById('updateServiceType').value = tracking.serviceType || '';
        document.getElementById('updateRecipientAddress').value = tracking.recipientAddress || '';
        document.getElementById('updateSpecialHandling').value = tracking.specialHandling || '';
        document.getElementById('updateExpectedDeliveryDate').value = tracking.expectedDeliveryDate || '';
        document.getElementById('updateExpectedDeliveryTime').value = tracking.expectedDeliveryTime || '';
        document.getElementById('updateOrigin').value = tracking.origin || '';
        document.getElementById('updateDestination').value = tracking.destination || '';
        document.getElementById('updateWeight').value = tracking.weight || '';

        // Update status indicator for the edit form
// In loadTrackingForEdit function:
document.getElementById('updateIsBlinkingOriginal').checked = tracking.isBlinking || false;
        // Render history for the selected tracking
        renderTrackingHistory(tracking.history, tracking._id);
        M.updateTextFields(); // Important for Materialize to correctly show populated fields
    } else {
        updateTrackingForm.style.display = 'none';
        document.getElementById('trackingHistoryList').querySelector('ul').innerHTML = '<li>No tracking selected or data found.</li>';
    }
}

function populateTrackingSelects() {
    const singleTrackingIdSelect = document.getElementById('singleTrackingIdSelect');
    const emailTrackingIdSelect = document.getElementById('emailTrackingIdSelect');
    const attachFileTrackingIdSelect = document.getElementById('attachFileTrackingIdSelect');

    const selects = [singleTrackingIdSelect, emailTrackingIdSelect, attachFileTrackingIdSelect].filter(s => s !== null);

    selects.forEach(select => {
        select.innerHTML = '<option value="" disabled selected>Select Tracking ID</option>';
        trackings.forEach(tracking => {
            const option = document.createElement('option');
            option.value = tracking.trackingId; // Use trackingId for select value
            option.dataset.mongoId = tracking._id; // Store mongoId for later retrieval
            option.textContent = tracking.trackingId;
            select.appendChild(option);
        });
    });
    M.FormSelect.init(document.querySelectorAll('select')); // Re-initialize Materialize selects
}

// Event listener for singleTrackingIdSelect to load data into edit form
function attachSingleTrackingSelectListener() {
    const singleTrackingIdSelect = document.getElementById('singleTrackingIdSelect');
    if (singleTrackingIdSelect) {
        singleTrackingIdSelect.addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            const mongoId = selectedOption ? selectedOption.dataset.mongoId : null;
            if (mongoId) {
                loadTrackingForEdit(mongoId);
            } else {
                document.getElementById('updateTrackingForm').style.display = 'none';
                document.getElementById('trackingHistoryList').querySelector('ul').innerHTML = '<li>No history entries yet.</li>';
            }
        });
    }
}

// Event listener for emailTrackingIdSelect to pre-fill recipient email
function attachEmailTrackingSelectListener() {
    const emailTrackingIdSelect = document.getElementById('emailTrackingIdSelect');
    const notificationEmailInput = document.getElementById('notificationEmail');
    if (emailTrackingIdSelect && notificationEmailInput) {
        emailTrackingIdSelect.addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            const trackingId = selectedOption ? selectedOption.value : null;
            const tracking = trackings.find(t => t.trackingId === trackingId);
            if (tracking && tracking.recipientEmail) {
                notificationEmailInput.value = tracking.recipientEmail;
            } else {
                notificationEmailInput.value = '';
            }
            M.updateTextFields(); // Trigger Materialize input label to move up/down
        });
    }
}


// --- Main Dashboard Initialization ---

async function initializeDashboard() {
    if (!isAuthenticated() || !hasAdminPrivileges()) {
        logout(); // Redirect to login if not authenticated or not an admin
        return;
    }

    // Set active section on load (default to dashboard)
    const activeSection = localStorage.getItem('activeDashboardSection') || 'dashboard-section';
    document.querySelectorAll('.dashboard-section').forEach(section => {
        section.classList.remove('active-section');
    });
    document.getElementById(activeSection).classList.add('active-section');

    document.querySelectorAll('.sidebar ul li a').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.section === activeSection) {
            link.classList.add('active');
        }
    });

    // Fetch and update all dashboard data
    await fetchAllTrackings(); // Populates the global `trackings` array
    updateDashboardStats();
    renderAllTrackingsTable(); // Renders table using the fetched `trackings`
    populateTrackingSelects(); // Populates dropdowns using the fetched `trackings`

    // Apply status indicator for Add New Tracking (initial render)
    updateStatusIndicator('addStatus', 'addStatusCircle', 'addIsBlinking');
    // For update form, the indicator is applied when a tracking is loaded
}


document.addEventListener('DOMContentLoaded', function() {
    // --- Initial Materialize Component Setup ---
    M.Sidenav.init(document.querySelectorAll('.sidenav'));
    M.Modal.init(document.querySelectorAll('.modal'));
    M.FormSelect.init(document.querySelectorAll('select'));
    M.Datepicker.init(document.querySelectorAll('.datepicker'), {
        format: 'yyyy-mm-dd'
    });
    M.Timepicker.init(document.querySelectorAll('.timepicker'), {
        twelveHour: false // Use 24-hour format for easier backend handling
    });

    // --- DOM Element References (after Materialize init) ---
    const addTrackingForm = document.getElementById('addTrackingForm');
    const updateTrackingForm = document.getElementById('updateTrackingForm');
    const addHistoryForm = document.getElementById('addHistoryForm');
    const saveHistoryEditBtn = document.getElementById('saveHistoryEditBtn');
    const closeEditHistoryModalBtn = document.getElementById('closeEditHistoryModalBtn');
    const sendEmailForm = document.getElementById('sendEmailForm');
    const uploadPackageFileForm = document.getElementById('uploadPackageFileForm');


    // --- Attach Event Listeners ---

    // Sidebar navigation
    document.querySelectorAll('.sidebar ul li a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetSectionId = this.dataset.section;

            document.querySelectorAll('.dashboard-section').forEach(section => {
                section.classList.remove('active-section');
            });
            document.getElementById(targetSectionId).classList.add('active-section');

            document.querySelectorAll('.sidebar ul li a').forEach(navLink => {
                navLink.classList.remove('active');
            });
            this.classList.add('active');

            localStorage.setItem('activeDashboardSection', targetSectionId); // Remember active section
        });
    });

    // Logout Button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Form Submissions
    if (addTrackingForm) addTrackingForm.addEventListener('submit', handleAddTrackingForm);
    if (updateTrackingForm) updateTrackingForm.addEventListener('submit', handleUpdateTrackingForm);
    if (addHistoryForm) addHistoryForm.addEventListener('submit', handleAddHistoryForm);
    if (saveHistoryEditBtn) saveHistoryEditBtn.addEventListener('click', handleSaveHistoryEdit);
    if (sendEmailForm) sendEmailForm.addEventListener('submit', handleSendEmailForm);
    if (uploadPackageFileForm) uploadPackageFileForm.addEventListener('submit', handleUploadPackageFileForm);

    // Close History Edit Modal
    const editHistoryModal = document.getElementById('editHistoryModal');
    if (closeEditHistoryModalBtn && editHistoryModal) {
        closeEditHistoryModalBtn.addEventListener('click', function() {
            M.Modal.getInstance(editHistoryModal).close();
        });
    }

    // Attach listeners for dynamically rendered elements
    attachTableButtonListeners(); // For View/Edit and Delete buttons in All Trackings table
    attachHistoryButtonListeners(); // For Edit/Delete buttons in Tracking History

    // Attach listeners for select elements that trigger form population
    attachSingleTrackingSelectListener();
    attachEmailTrackingSelectListener();

    // Initial Dashboard Load
    initializeDashboard();
});
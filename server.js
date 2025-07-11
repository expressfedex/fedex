const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const multer = require('multer'); // For file uploads
const nodemailer = require('nodemailer'); // For sending emails

// --- IMPORTANT: Remove or comment out this line for Render deployments ---
// On Render, environment variables are automatically injected into process.env.
// Keeping this line might cause issues if a local .env file is not present
// or if it interferes with Render's environment variable injection.
// require('dotenv').config();


const app = express();

// --- Define the PORT variable first ---
// Render provides a PORT environment variable. Use it, or a fallback for local.
const PORT = process.env.PORT || 5000;


// --- MongoDB Connection - This is the SINGLE, CORRECTED connection block ---
// The entire app setup and server start will now happen *after* successful connection.
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('MongoDB connected successfully! 🚀');

    // --- ONLY START THE SERVER AND POPULATE DATA AFTER A SUCCESSFUL DB CONNECTION ---
    app.listen(PORT, () => {
        // Corrected log for Render: just specify the port, not localhost
        console.log(`Server running on port ${PORT}`);
        console.log(`Server JWT_SECRET (active): ${process.env.JWT_SECRET ? 'Loaded' : 'Not Loaded'}`);
    });

    // --- Initial Data Population (Optional, for testing) ---
    // Call this ONLY after the database connection is confirmed
    populateInitialData();
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    // It's good practice to exit the process if the database connection fails
    // as the app won't function without it.
    process.exit(1);
});


// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// --- Mongoose Schemas and Models ---
// (These remain unchanged, but their definition order is important before routes)

const trackingHistorySchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    location: { type: String, default: '' },
    description: { type: String, required: true }
});

const TrackingSchema = new mongoose.Schema({
    trackingId: { type: String, required: true, unique: true },
    status: { type: String, required: true },
    statusLineColor: { type: String, default: '#2196F3' }, // Default blue
    blinkingDotColor: { type: String, default: '#FFFFFF' }, // Default white
    isBlinking: { type: Boolean, default: false },
    origin: { type: String, default: '' },
    destination: { type: String, default: '' },
    expectedDelivery: { type: Date },
    senderName: { type: String, default: '' },
    recipientName: { type: String, default: '' },
    recipientEmail: { type: String, default: '' }, // Added recipientEmail field
    packageContents: { type: String, default: '' },
    serviceType: { type: String, default: '' },
    recipientAddress: { type: String, default: '' },
    specialHandling: { type: String, default: '' },
    weight: { type: Number, default: 0 }, // in kg or lbs
    history: [trackingHistorySchema],
    attachedFileName: { type: String, default: null }, // Stores the filename of the attached document
    lastUpdated: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

// Hash password before saving
UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const Tracking = mongoose.model('Tracking', TrackingSchema);
const User = mongoose.model('User', UserSchema);


// --- Initial Data Population (Optional, for testing) ---
// This function needs to be defined BEFORE its call in the .then() block of mongoose.connect
async function populateInitialData() {
    try {
        const existingTracking = await Tracking.findOne({ trackingId: '7770947003939' });
        if (existingTracking) {
            console.log('Tracking data already exists. Skipping initial population.');
            return;
        }

        const newTracking = new Tracking({
            trackingId: '7770947003939',
            status: 'FedEx Hub',
            statusLineColor: '#14b31e', // Green
            blinkingDotColor: '#b93737', // Red
            isBlinking: true,
            origin: 'Texas, USA',
            destination: 'Guangzhou, China',
            expectedDelivery: new Date('2025-07-13T00:00:00Z'),
            senderName: 'UNDEF Program',
            recipientName: 'David R Fox',
            recipientEmail: 'mistycpayne@gmail.com', // Added recipient email for initial data
            packageContents: '$250,000 USD',
            serviceType: 'Express',
            recipientAddress: 'Hollywood, Barangay Narvarte, Nibaliw west. San Fabian, Pangasinan, Philippines ,2433.',
            specialHandling: 'Signatured Required',
            weight: 30, // kg
            history: [
                { location: 'Origin', description: 'Shipment created' }
            ]
        });
        await newTracking.save();
        console.log('New tracking added to MongoDB:', newTracking.toObject());
    } catch (error) {
        console.error('Error populating initial data:', error);
    }
}


// --- JWT Authentication Middleware ---
console.log('Server JWT_SECRET (active):', process.env.JWT_SECRET ? 'Loaded' : 'Not Loaded'); // Improved log
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ message: 'Token required.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired. Please log in again.' });
            }
            return res.status(403).json({ message: 'Invalid token.' });
        }
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    authenticateToken(req, res, () => {
        if (req.user && req.user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ message: 'Access denied. Admin privileges required.' });
        }
    });
};


// --- User Authentication Routes ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' } // Token expires in 24 hour
        );
        res.json({ message: 'Logged in successfully!', token, role: user.role });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});


// --- Multer for File Uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        // Ensure the directory exists
        require('fs').mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        // Use a more unique name, e.g., timestamp + original name
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage: storage });

// Route for file upload
app.post('/api/admin/upload-package-file', authenticateAdmin, upload.single('packageFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }
    const { trackingId } = req.body;

    if (!trackingId) {
        // If trackingId is missing but file is uploaded, delete the file
        require('fs').unlink(req.file.path, (err) => {
            if (err) console.error('Error deleting uploaded file:', err);
        });
        return res.status(400).json({ message: 'Tracking ID is required to link the file.' });
    }

    try {
        const tracking = await Tracking.findOne({ trackingId });
        if (!tracking) {
            // If tracking ID not found, delete the file
            require('fs').unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting uploaded file for non-existent tracking:', err);
            });
            return res.status(404).json({ message: 'Tracking ID not found. File not linked.' });
        }

        // Store only the filename (relative path to 'uploads' directory)
        // If an old file exists, you might want to delete it first to save space
        if (tracking.attachedFileName) {
            const oldFilePath = path.join(__dirname, 'uploads', tracking.attachedFileName);
            if (require('fs').existsSync(oldFilePath)) {
                require('fs').unlink(oldFilePath, (err) => {
                    if (err) console.error('Error deleting old attached file:', err);
                });
            }
        }
        tracking.attachedFileName = req.file.filename;
        tracking.lastUpdated = new Date();
        await tracking.save();
        res.json({ message: 'File uploaded and linked successfully!', fileName: req.file.filename });
    } catch (error) {
        console.error('Error linking file to tracking:', error);
        // Clean up uploaded file if linking fails
        require('fs').unlink(req.file.path, (err) => {
            if (err) console.error('Error deleting uploaded file after database error:', err);
        });
        res.status(500).json({ message: 'Server error while linking file.' });
    }
});

// --- Nodemailer for Email Sending ---
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can use other services or SMTP
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.post('/api/admin/send-email', authenticateAdmin, upload.single('attachment'), async (req, res) => {
    const { to, subject, body, trackingId } = req.body;

    if (!to || !subject || !body) {
        if (req.file) {
            require('fs').unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting temp email attachment due to missing fields:', err);
            });
        }
        return res.status(400).json({ message: 'Recipient, Subject, and Message are required.' });
    }

    let attachments = [];
    if (req.file) {
        attachments.push({
            filename: req.file.originalname,
            path: req.file.path
        });
    } else if (trackingId) {
        try {
            const tracking = await Tracking.findOne({ trackingId });
            if (tracking && tracking.attachedFileName) {
                const filePath = path.join(__dirname, 'uploads', tracking.attachedFileName);
                if (require('fs').existsSync(filePath)) {
                    attachments.push({
                        filename: tracking.attachedFileName,
                        path: filePath
                    });
                } else {
                    console.warn(`Attached file for tracking ID ${trackingId} not found on disk: ${filePath}`);
                }
            } else {
                console.warn(`No attached file found for tracking ID: ${trackingId}`);
            }
        } catch (error) {
            console.error('Error fetching attached file for email:', error);
        }
    }

    // --- HTML Email Template with White and Purple Glowing Colors ---
    const htmlEmailBody = `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #0d1117; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 20px;">
                <h1 style="color: #ffffff; text-shadow: 0 0 5px #fff, 0 0 10px #fff, 0 0 15px #bb00ff, 0 0 20px #bb00ff; animation: glow-white-purple 1.5s infinite alternate;">
                    Tracking Update Notification
                </h1>
                <style>
                    @keyframes glow-white-purple {
                        from { text-shadow: 0 0 5px #fff, 0 0 10px #fff, 0 0 15px #bb00ff, 0 0 20px #bb00ff; }
                        to { text-shadow: 0 0 10px #fff, 0 0 20px #fff, 0 0 30px #bb00ff, 0 0 40px #bb00ff; }
                    }
                </style>
            </div>
            <div style="background-color: #161b22; padding: 15px; border-radius: 5px; border: 1px solid #30363d;">
                <p style="color: #e6e6e6;">Dear recipient,</p>
                <p style="color: #e6e6e6;">You have received an important update regarding your package.</p>
                <p style="color: #e6e6e6;"><strong>Subject:</strong> ${subject}</p>
                <p style="color: #e6e6e6;"><strong>Message:</strong></p>
                <div style="padding: 10px; background-color: #21262d; border-radius: 4px; border: 1px solid #444c56; color: #c9d1d9;">
                    <p style="margin: 0;">${body.replace(/\n/g, '<br>')}</p>
                </div>
                ${trackingId ? `<p style="color: #e6e6e6; margin-top: 15px;">You can view detailed tracking information here: <a href="${process.env.FRONTEND_URL}/track_details.html?trackingId=${trackingId}" style="color: #bb00ff; text-decoration: none;">Track Your Package</a></p>` : ''}
                <p style="color: #e6e6e6; margin-top: 20px;">Thank you for your patience.</p>
                <p style="color: #e6e6e6; font-size: 0.9em;">Best regards,<br>Your Shipping Team</p>
            </div>
        </div>
    `;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: subject,
        html: htmlEmailBody, // Use the HTML email body
        attachments: attachments
    };

    try {
        await transporter.sendMail(mailOptions);
        if (req.file) {
            require('fs').unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting temporary uploaded email attachment:', err);
            });
        }
        res.json({ message: 'Email sent successfully!' });
    } catch (error) {
        console.error('Error sending email:', error);
        if (req.file) {
            require('fs').unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting temporary uploaded email attachment after send failure:', err);
            });
        }
        res.status(500).json({ message: 'Server error while sending email.', error: error.message });
    }
});


// --- Admin Dashboard Stats API ---
app.get('/api/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalPackages = await Tracking.countDocuments({});
        const delivered = await Tracking.countDocuments({ status: { $regex: /delivered/i } });
        const inTransit = await Tracking.countDocuments({ status: { $regex: /in transit|in-transit/i } }); // Include common variations
        const pending = await Tracking.countDocuments({ status: { $regex: /pending|hold/i } }); // Include common variations
        const exceptions = await Tracking.countDocuments({ status: { $regex: /exception|failed|returned/i } }); // Combined for better accuracy

        res.json({
            totalPackages,
            delivered,
            inTransit,
            pending,
            exceptions
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ message: 'Server error while fetching dashboard stats.' });
    }
});


// --- Admin Tracking Management Routes ---

// Endpoint to verify admin token
app.get('/api/admin/verify-token', authenticateAdmin, (req, res) => {
    res.json({ message: 'Token is valid', user: { username: req.user.username, role: req.user.role } });
});

// Admin Route to get all tracking records from MongoDB
app.get('/api/admin/trackings', authenticateAdmin, async (req, res) => {
    try {
        const trackings = await Tracking.find({});
        res.json(trackings);
    } catch (error) {
        console.error('Error fetching all tracking records:', error);
        res.status(500).json({ message: 'Server error while fetching all tracking data.' });
    }
});

// Admin Route to get a single tracking by ID (for admin editing)
// Note: This endpoint uses the actual MongoDB _id for lookup for robustness
app.get('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params; // Expecting MongoDB _id here
    try {
        const tracking = await Tracking.findById(id); // Use findById for _id lookup
        if (tracking) {
            res.json(tracking);
        } else {
            res.status(404).json({ message: 'Tracking record not found.' });
        }
    } catch (error) {
        console.error(`Error fetching single tracking data for admin (ID: ${id}):`, error);
        if (error.name === 'CastError') { // Handle invalid MongoDB ID format
            return res.status(400).json({ message: 'Invalid tracking ID format.' });
        }
        res.status(500).json({ message: 'Server error while fetching tracking data.' });
    }
});


// Admin Route to create a new tracking record
app.post('/api/admin/trackings', authenticateAdmin, async (req, res) => {
    const {
        trackingId, status, description, origin, destination, expectedDeliveryDate, expectedDeliveryTime, // Changed to match frontend
        senderName, recipientName, recipientEmail, packageContents, serviceType,
        recipientAddress, specialHandling, weight, history,
        statusLineColor, blinkingDotColor, isBlinking
    } = req.body;

    // Basic validation
    if (!trackingId || !status) {
        return res.status(400).json({ message: 'Tracking ID and Status are required.' });
    }

    try {
        const existingTracking = await Tracking.findOne({ trackingId });
        if (existingTracking) {
            return res.status(409).json({ message: 'Tracking ID already exists.' });
        }

        // Combine date and time for expectedDelivery if both are provided
        let expectedDelivery = null;
        if (expectedDeliveryDate) {
            // Validate date format (YYYY-MM-DD)
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
            if (!dateRegex.test(expectedDeliveryDate)) {
                return res.status(400).json({ message: 'Invalid expectedDeliveryDate format. Expected YYYY-MM-DD.' });
            }
            if (expectedDeliveryTime) {
                // Validate time format (HH:MM)
                const timeRegex = /^(?:2[0-3]|[01]?[0-9]):[0-5][0-9]$/;
                if (!timeRegex.test(expectedDeliveryTime)) {
                    return res.status(400).json({ message: 'Invalid expectedDeliveryTime format. Expected HH:MM.' });
                }
                expectedDelivery = new Date(`${expectedDeliveryDate}T${expectedDeliveryTime}:00`);
            } else {
                expectedDelivery = new Date(expectedDeliveryDate);
            }
        }

        const newTracking = new Tracking({
            trackingId,
            status,
            description, // Ensure description is saved
            origin,
            destination,
            expectedDelivery: expectedDelivery, // Use the combined date object
            senderName,
            recipientName,
            recipientEmail, // Save recipient email
            packageContents,
            serviceType,
            recipientAddress,
            specialHandling,
            weight,
            history: history || [], // Ensure history is initialized
            statusLineColor: statusLineColor || '#2196F3',
            blinkingDotColor: blinkingDotColor || '#FFFFFF',
            isBlinking: typeof isBlinking === 'boolean' ? isBlinking : false,
            lastUpdated: new Date() // Set last updated on creation
        });

        await newTracking.save();
        res.status(201).json({ message: 'Tracking added successfully!', tracking: newTracking });
    } catch (error) {
        console.error('Error adding new tracking:', error);
        res.status(500).json({ message: 'Server error while adding new tracking.', error: error.message });
    }
});


// Public Route to get a single tracking by ID (No Authentication)
app.get('/api/track/:trackingId', async (req, res) => {
    const { trackingId } = req.params;
    console.log(`Received public request for tracking ID: ${trackingId}`);
    try {
        const tracking = await Tracking.findOne({ trackingId });
        if (tracking) {
            res.json({
                ...tracking.toObject(),
                statusLineColor: tracking.statusLineColor || '#2196F3',
                blinkingDotColor: tracking.blinkingDotColor || '#FFFFFF',
                isBlinking: tracking.isBlinking,
                // Construct a public URL for the attached file if it exists
                attachedFileUrl: tracking.attachedFileName ? `/uploads/${tracking.attachedFileName}` : null
            });
        } else {
            res.status(404).json({ message: 'Tracking ID not found.' });
        }
    } catch (error) {
        console.error('Error fetching tracking data:', error);
        res.status(500).json({ message: 'Server error while fetching tracking data.' });
    }
});


// Add new history events to a tracking record
// NOTE: Frontend sends newHistoryEvent as {date, time, location, description}
app.post('/api/admin/trackings/:id/history', authenticateAdmin, async (req, res) => { // Changed method to POST and param to :id
    const { id } = req.params; // This is the MongoDB _id
    const { date, time, location, description } = req.body; // Expecting individual fields

    // --- ENHANCED VALIDATION FOR ADDING HISTORY ---
    if (!description || description.trim() === '') {
        return res.status(400).json({ message: 'History event description is required.' });
    }

    if (!date || date.trim() === '') {
        return res.status(400).json({ message: 'History event date is required.' });
    }
    if (!time || time.trim() === '') {
        return res.status(400).json({ message: 'History event time is required.' });
    }

    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(date)) {
        return res.status(400).json({ message: 'Invalid date format for new history event. Expected YYYY-MM-DD.' });
    }
    const timeRegex = /^(?:2[0-3]|[01]?[0-9]):[0-5][0-9]$/;
    if (!timeRegex.test(time)) {
        return res.status(400).json({ message: 'Invalid time format for new history event. Expected HH:MM.' });
    }

    const combinedTimestamp = `${date}T${time}:00`;

    try {
        const tracking = await Tracking.findById(id); // Use findById for robustness

        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        // Ensure history array exists
        if (!tracking.history) {
            tracking.history = [];
        }

        const newHistoryItem = {
            timestamp: new Date(combinedTimestamp),
            location: location || '',
            description: description
        };

        tracking.history.push(newHistoryItem);

        // Sort history by timestamp (optional but good practice)
        tracking.history.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        tracking.lastUpdated = new Date();
        await tracking.save();

        // Return the newly added history item, including its MongoDB _id
        // This is important for the frontend to manage edits/deletes
        res.status(201).json({ message: 'History event added successfully!', historyEvent: tracking.history[tracking.history.length -1] }); // Send the last added event (which will have the _id)
    } catch (error) {
        console.error('Error adding history event:', error);
        res.status(500).json({ message: 'Server error while adding history event.', error: error.message });
    }
});


// Edit a specific history event
app.put('/api/admin/trackings/:id/history/:historyId', authenticateAdmin, async (req, res) => {
    const { id, historyId } = req.params; // tracking ID (MongoDB _id) and history event ID
    const { date, time, location, description } = req.body;

    if (date === undefined && time === undefined && location === undefined && description === undefined) {
        return res.status(400).json({ message: 'At least one field (date, time, location, or description) is required to update a history event.' });
    }

    try {
        const tracking = await Tracking.findById(id);

        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        // Find the specific history event by its _id (from the subdocument array)
        const historyEvent = tracking.history.id(historyId);

        if (!historyEvent) {
            return res.status(404).json({ message: 'History event not found.' });
        }

        if (location !== undefined) historyEvent.location = location;
        if (description !== undefined) historyEvent.description = description;

        let newTimestamp;
        if (date !== undefined || time !== undefined) {
            const effectiveDate = date !== undefined ? date : historyEvent.timestamp.toISOString().split('T')[0];
            const effectiveTime = time !== undefined ? time : historyEvent.timestamp.toISOString().split('T')[1].substring(0, 5);

            const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
            const timeRegex = /^(?:2[0-3]|[01]?[0-9]):[0-5][0-9]$/;

            if (date !== undefined && !dateRegex.test(effectiveDate)) {
                return res.status(400).json({ message: 'Invalid date format for history event update. Expected YYYY-MM-DD.' });
            }
            if (time !== undefined && !timeRegex.test(effectiveTime)) {
                return res.status(400).json({ message: 'Invalid time format for history event update. Expected HH:MM.' });
            }

            newTimestamp = new Date(`${effectiveDate}T${effectiveTime}:00`);
            if (isNaN(newTimestamp.getTime())) {
                return res.status(400).json({ message: 'Invalid date or time provided for history event update.' });
            }
            historyEvent.timestamp = newTimestamp;
        }

        tracking.history.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        tracking.lastUpdated = new Date();
        await tracking.save();

        res.json({ message: 'History event updated successfully!', historyEvent: historyEvent.toObject() }); // Return the updated subdocument
    } catch (error) {
        console.error(`Error updating history event ${historyId} for tracking ID ${id}:`, error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid ID format for tracking or history event.' });
        }
        res.status(500).json({ message: 'Server error while updating history event.', error: error.message });
    }
});


// Admin Route to Update Tracking Details (general updates, including trackingId change)
// NOTE: This endpoint now primarily uses the MongoDB _id from the URL for robustness
app.put('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params; // This is the MongoDB _id from the URL
    const updateData = req.body;

    try {
        let currentTracking = await Tracking.findById(id); // Find by MongoDB _id

        if (!currentTracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        // Logic to handle changing the trackingId itself (if `trackingId` is in updateData and different)
        if (updateData.trackingId && updateData.trackingId !== currentTracking.trackingId) {
            const newTrackingId = updateData.trackingId;

            // Check if the newTrackingId already exists for *another* document
            const existingTrackingWithNewId = await Tracking.findOne({ trackingId: newTrackingId });
            if (existingTrackingWithNewId && String(existingTrackingWithNewId._id) !== id) { // Ensure it's not the same document
                return res.status(409).json({ message: 'New Tracking ID already exists. Please choose a different one.' });
            }
            currentTracking.trackingId = newTrackingId;
            // Removed console.log(`Tracking ID changed from ${trackingId} to ${newTrackingId}`);
            // because `trackingId` was not defined in this scope.
            // If you want to log, use `currentTracking.trackingId` BEFORE the change.
            console.log(`Tracking ID changed from (old): ${currentTracking.trackingId} to (new): ${newTrackingId}`);
        }

        // Update fields based on updateData
        Object.keys(updateData).forEach(key => {
            // Skip updating internal IDs or history via this general update endpoint
            if (key === 'trackingId' || key === 'history' || key === '_id' || key === '__v' || updateData[key] === undefined) {
                return;
            }

            if (key === 'expectedDeliveryDate') {
                // Handle expectedDelivery combining date and time
                const effectiveDate = updateData.expectedDeliveryDate;
                const effectiveTime = updateData.expectedDeliveryTime || (currentTracking.expectedDelivery ? currentTracking.expectedDelivery.toISOString().split('T')[1].substring(0, 5) : '00:00'); // Use existing time or default

                if (effectiveDate) {
                    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
                    if (!dateRegex.test(effectiveDate)) {
                        console.warn(`Invalid date format for expectedDeliveryDate: ${effectiveDate}`);
                        return; // Skip invalid date
                    }
                    const newExpectedDelivery = new Date(`${effectiveDate}T${effectiveTime}:00`);
                    if (!isNaN(newExpectedDelivery.getTime())) {
                        currentTracking.expectedDelivery = newExpectedDelivery;
                    } else {
                        console.warn(`Could not parse new expectedDelivery: ${effectiveDate} ${effectiveTime}`);
                    }
                }
            } else if (key === 'expectedDeliveryTime') {
                // If only time is updated, combine with existing date
                if (updateData.expectedDeliveryDate === undefined) { // Only update if date wasn't part of the same request
                    const effectiveDate = currentTracking.expectedDelivery ? currentTracking.expectedDelivery.toISOString().split('T')[0] : (new Date().toISOString().split('T')[0]); // Use existing date or today
                    const effectiveTime = updateData.expectedDeliveryTime;

                    if (effectiveTime) {
                        const timeRegex = /^(?:2[0-3]|[01]?[0-9]):[0-5][0-9]$/;
                        if (!timeRegex.test(effectiveTime)) {
                            console.warn(`Invalid time format for expectedDeliveryTime: ${effectiveTime}`);
                            return; // Skip invalid time
                        }
                        const newExpectedDelivery = new Date(`${effectiveDate}T${effectiveTime}:00`);
                        if (!isNaN(newExpectedDelivery.getTime())) {
                            currentTracking.expectedDelivery = newExpectedDelivery;
                        } else {
                            console.warn(`Could not parse new expectedDelivery with existing date: ${effectiveDate} ${effectiveTime}`);
                        }
                    }
                }
            } else if (key === 'isBlinking') {
                currentTracking.isBlinking = typeof updateData[key] === 'boolean' ? updateData[key] : currentTracking.isBlinking;
            } else if (key === 'weight') {
                currentTracking.weight = parseFloat(updateData.weight) || 0;
            } else {
                currentTracking[key] = updateData[key];
            }
        });

        currentTracking.lastUpdated = new Date();
        await currentTracking.save();
        res.json({ message: 'Tracking updated successfully!', tracking: currentTracking });
    } catch (error) {
        console.error('Error updating tracking details:', error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid tracking ID format.' });
        }
        res.status(500).json({ message: 'Server error when updating tracking details.', error: error.message });
    }
});


// Delete a specific history event by _id
app.delete('/api/admin/trackings/:id/history/:historyId', authenticateAdmin, async (req, res) => {
    const { id, historyId } = req.params; // Get tracking's MongoDB _id and history event _id

    try {
        const tracking = await Tracking.findById(id);
        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        const historyLengthBeforePull = tracking.history.length;
        tracking.history.pull({ _id: historyId }); // Use Mongoose's pull method to remove subdocument by _id

        if (tracking.history.length === historyLengthBeforePull) {
            return res.status(404).json({ message: 'History event not found with the provided ID.' });
        }

        tracking.lastUpdated = new Date();
        await tracking.save();
        res.json({ message: 'History event deleted successfully!', tracking });
    } catch (error) {
        console.error('Error deleting history event:', error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid ID format for tracking or history event.' });
        }
        res.status(500).json({ message: 'Server error while deleting history event.', error: error.message });
    }
});


// Delete an entire tracking record
// NOTE: This endpoint now uses the MongoDB _id from the URL for robustness
app.delete('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params; // Expecting MongoDB _id here
    try {
        // Find the tracking record first to get its `trackingId` and handle associated files
        const trackingToDelete = await Tracking.findById(id);
        if (!trackingToDelete) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        // If an attached file exists, delete it from the server
        if (trackingToDelete.attachedFileName) {
            const filePath = path.join(__dirname, 'uploads', trackingToDelete.attachedFileName);
            if (require('fs').existsSync(filePath)) {
                require('fs').unlink(filePath, (err) => {
                    if (err) console.error(`Error deleting attached file ${filePath}:`, err);
                });
            }
        }

        const result = await Tracking.deleteOne({ _id: id }); // Delete by MongoDB _id
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }
        res.json({ message: 'Tracking deleted successfully!' });
    } catch (error) {
        console.error('Error deleting tracking:', error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid tracking ID format.' });
        }
        res.status(500).json({ message: 'Error deleting tracking data.', error: error.message });
    }
});


// --- Initial User Creation ---
// IMPORTANT: This route should be protected or removed after initial admin user creation in a production environment.
// For initial setup, you might run it once and then remove/protect it.
app.post('/api/admin/create-user', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'User already exists.' });
        }

        if (role && !['user', 'admin'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role specified. Must be "user" or "admin".' });
        }

        const newUser = new User({ username, password, role: role || 'user' });
        await newUser.save();
        res.status(201).json({ message: 'User created successfully!', user: { username: newUser.username, role: newUser.role } });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ message: 'Error creating user.' });
    }
});


// --- Serve Static HTML Files ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin_login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin_login.html'));
});

app.get('/admin_dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'));
});

app.get('/track_details.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'track_details.html'));
});


// Universal 404 handler (optional, but good practice)
app.use((req, res, next) => {
    res.status(404).json({ message: 'Endpoint not found.' });
});


// Error handling middleware (should be last)
app.use((err, req, res, next) => {
    console.error(err.stack); // Log the error stack for debugging
    res.status(err.statusCode || 500).json({
        message: err.message || 'An unexpected error occurred on the server.',
        error: process.env.NODE_ENV === 'production' ? {} : err.stack // Avoid sending stack trace in production
    });
});

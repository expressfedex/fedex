const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
// const multer = require('multer'); // We'll replace Multer's disk storage
const nodemailer = require('nodemailer');
const serverless = require('serverless-http'); // Import serverless-http

// --- For Cloudinary Integration (install these: npm install cloudinary multer-storage-cloudinary) ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer'); // Multer is still used, but with Cloudinary storage

// --- Configure Cloudinary ---
// These will come from Netlify Environment Variables
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Multer to use Cloudinary storage
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'fedex-uploads', // Specify a folder in Cloudinary
        format: async (req, file) => 'pdf', // Supports 'png', 'jpeg', 'pdf' etc.
        public_id: (req, file) => `${Date.now()}-${file.originalname.replace(/\s+/g, '-')}`, // Unique public ID
    },
});
const upload = multer({ storage: storage });


const app = express();

// --- MongoDB Connection ---
let cachedDb = null; // Cache the DB connection

async function connectToDatabase() {
    if (cachedDb) {
        return cachedDb;
    }
    const connection = await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000 // Keep trying for 5 seconds
    });
    cachedDb = connection;
    console.log('MongoDB connected successfully!');
    return cachedDb;
}

// --- Middleware ---
const corsOptions = {
    origin: process.env.FRONTEND_URL, // <--- Use the FRONTEND_URL from env vars
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// --- IMPORTANT: Remove static file serving for '/uploads' ---
// Netlify Functions cannot serve static files from a local 'uploads' directory.
// Files will be served directly from Cloudinary.
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// --- Mongoose Schemas and Models ---
// These should ideally be in separate files (e.g., models/Tracking.js, models/User.js)
// and then required here. For now, keeping them in place for simplicity.
const trackingHistorySchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    location: { type: String, default: '' },
    description: { type: String, required: true }
});

const TrackingSchema = new mongoose.Schema({
    trackingId: { type: String, required: true, unique: true },
    status: { type: String, required: true },
    statusLineColor: { type: String, default: '#2196F3' },
    blinkingDotColor: { type: String, default: '#FFFFFF' },
    isBlinking: { type: Boolean, default: false },
    origin: { type: String, default: '' },
    destination: { type: String, default: '' },
    expectedDelivery: { type: Date },
    senderName: { type: String, default: '' },
    recipientName: { type: String, default: '' },
    recipientEmail: { type: String, default: '' },
    packageContents: { type: String, default: '' },
    serviceType: { type: String, default: '' },
    recipientAddress: { type: String, default: '' },
    specialHandling: { type: String, default: '' },
    weight: { type: Number, default: 0 },
    history: [trackingHistorySchema],
    attachedFileName: { type: String, default: null }, // Stores the Cloudinary public_id or URL
    lastUpdated: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const Tracking = mongoose.model('Tracking', TrackingSchema);
const User = mongoose.model('User', UserSchema);


// --- Initial Data Population (Optional, for testing) ---
// This function will run on every cold start of a function.
// Consider removing it or making it an independent script for production.
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
            origin: 'Massachusetts, USA',
            destination: 'Guangzhou, China',
            expectedDelivery: new Date('2025-07-12T00:00:00Z'),
            senderName: 'UNDEF Program',
            recipientName: 'David R Fox',
            recipientEmail: 'mistycpayne@gmail.com',
            packageContents: '$250,000 USD',
            serviceType: 'Express',
            recipientAddress: 'Hollywood, Barangay Narvarte, Nibaliw west. San Fabian, Pangasinan, Philippines ,2433.',
            specialHandling: 'Signatured Required',
            weight: 30, // kg
            history: [
                { location: 'Guangzhou, China', description: 'Package on the Way' }
            ]
        });
        await newTracking.save();
        console.log('New tracking added to MongoDB:', newTracking.toObject());
    } catch (error) {
        console.error('Error populating initial data:', error);
    }
}

// --- Middleware to connect to DB and populate data for each function invocation ---
// This ensures DB connection on every request (or uses cached connection)
app.use(async (req, res, next) => {
    try {
        await connectToDatabase();
        // Only populate data once, or if needed for every cold start
        await populateInitialData();
        next();
    } catch (err) {
        console.error('Database connection/population failed:', err);
        res.status(500).json({ message: 'Internal Server Error: Database connection failed.' });
    }
});


// --- JWT Authentication Middleware ---
console.log('Server JWT_SECRET (active):', process.env.JWT_SECRET ? 'Loaded' : 'Not Loaded');
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
            { expiresIn: '24h' }
        );
        res.json({ message: 'Logged in successfully!', token, role: user.role });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});


// --- Route for File Upload to Cloudinary ---
app.post('/api/admin/upload-package-file', authenticateAdmin, upload.single('packageFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }
    const { trackingId } = req.body;

    if (!trackingId) {
        // Cloudinary handles cleanup if upload failed to link to DB
        // You might want to delete the file from Cloudinary if linking fails here
        // await cloudinary.uploader.destroy(req.file.filename); // Use filename (public_id)
        return res.status(400).json({ message: 'Tracking ID is required to link the file.' });
    }

    try {
        const tracking = await Tracking.findOne({ trackingId });
        if (!tracking) {
            // Delete file from Cloudinary if tracking ID not found
            await cloudinary.uploader.destroy(req.file.filename); // filename property holds public_id for Cloudinary storage
            return res.status(404).json({ message: 'Tracking ID not found. File not linked.' });
        }

        // If an old file exists, delete it from Cloudinary first to save space
        if (tracking.attachedFileName) {
            await cloudinary.uploader.destroy(tracking.attachedFileName); // attachedFileName will store public_id
        }

        // Store Cloudinary's public_id (for easy deletion/retrieval later)
        tracking.attachedFileName = req.file.filename; // Multer-Cloudinary sets .filename to Cloudinary's public_id
        tracking.lastUpdated = new Date();
        await tracking.save();
        res.json({ message: 'File uploaded and linked successfully!', fileName: req.file.filename, url: req.file.path }); // .path holds the Cloudinary URL
    } catch (error) {
        console.error('Error linking file to tracking:', error);
        // Clean up uploaded file from Cloudinary if linking fails
        if (req.file && req.file.filename) {
            await cloudinary.uploader.destroy(req.file.filename);
        }
        res.status(500).json({ message: 'Server error while linking file.' });
    }
});

// --- Nodemailer for Email Sending ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.post('/api/admin/send-email', authenticateAdmin, upload.single('attachment'), async (req, res) => {
    const { to, subject, body, trackingId } = req.body;

    if (!to || !subject || !body) {
        if (req.file) {
             // If a new file was uploaded for this email, delete it from Cloudinary
             await cloudinary.uploader.destroy(req.file.filename);
        }
        return res.status(400).json({ message: 'Recipient, Subject, and Message are required.' });
    }

    let attachments = [];
    if (req.file) {
        // If a new file was uploaded specifically for this email
        attachments.push({
            filename: req.file.originalname,
            path: req.file.path // Cloudinary URL
        });
    } else if (trackingId) {
        // If attaching a file already linked to a tracking record
        try {
            const tracking = await Tracking.findOne({ trackingId });
            if (tracking && tracking.attachedFileName) {
                // Construct Cloudinary URL from the stored public_id
                const cloudinaryFileUrl = cloudinary.url(tracking.attachedFileName, { secure: true, resource_type: 'raw' });
                attachments.push({
                    filename: tracking.attachedFileName, // Use public_id as filename for attachment
                    path: cloudinaryFileUrl
                });
            } else {
                console.warn(`No attached file found for tracking ID: ${trackingId}`);
            }
        } catch (error) {
            console.error('Error fetching attached file for email:', error);
        }
    }

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
        html: htmlEmailBody,
        attachments: attachments
    };

    try {
        await transporter.sendMail(mailOptions);
        if (req.file) {
            // Delete new file uploaded specifically for this email after sending
            await cloudinary.uploader.destroy(req.file.filename);
        }
        res.json({ message: 'Email sent successfully!' });
    } catch (error) {
        console.error('Error sending email:', error);
        if (req.file) {
            await cloudinary.uploader.destroy(req.file.filename);
        }
        res.status(500).json({ message: 'Server error while sending email.', error: error.message });
    }
});

// --- Admin Dashboard Stats API ---
app.get('/api/admin/dashboard-stats', authenticateAdmin, async (req, res) => {
    try {
        const totalPackages = await Tracking.countDocuments({});
        const delivered = await Tracking.countDocuments({ status: { $regex: /delivered/i } });
        const inTransit = await Tracking.countDocuments({ status: { $regex: /in transit|in-transit/i } });
        const pending = await Tracking.countDocuments({ status: { $regex: /pending|hold/i } });
        const exceptions = await Tracking.countDocuments({ status: { $regex: /exception|failed|returned/i } });

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
app.get('/api/admin/verify-token', authenticateAdmin, (req, res) => {
    res.json({ message: 'Token is valid', user: { username: req.user.username, role: req.user.role } });
});

app.get('/api/admin/trackings', authenticateAdmin, async (req, res) => {
    try {
        const trackings = await Tracking.find({});
        res.json(trackings);
    } catch (error) {
        console.error('Error fetching all tracking records:', error);
        res.status(500).json({ message: 'Server error while fetching all tracking data.' });
    }
});

app.get('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const tracking = await Tracking.findById(id);
        if (tracking) {
            res.json(tracking);
        } else {
            res.status(404).json({ message: 'Tracking record not found.' });
        }
    } catch (error) {
        console.error(`Error fetching single tracking data for admin (ID: ${id}):`, error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid tracking ID format.' });
        }
        res.status(500).json({ message: 'Server error while fetching tracking data.' });
    }
});

app.post('/api/admin/trackings', authenticateAdmin, async (req, res) => {
    const {
        trackingId, status, description, origin, destination, expectedDeliveryDate, expectedDeliveryTime,
        senderName, recipientName, recipientEmail, packageContents, serviceType,
        recipientAddress, specialHandling, weight, history,
        statusLineColor, blinkingDotColor, isBlinking
    } = req.body;

    if (!trackingId || !status) {
        return res.status(400).json({ message: 'Tracking ID and Status are required.' });
    }

    try {
        const existingTracking = await Tracking.findOne({ trackingId });
        if (existingTracking) {
            return res.status(409).json({ message: 'Tracking ID already exists.' });
        }

        let expectedDelivery = null;
        if (expectedDeliveryDate) {
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
            if (!dateRegex.test(expectedDeliveryDate)) {
                return res.status(400).json({ message: 'Invalid expectedDeliveryDate format. Expected YYYY-MM-DD.' });
            }
            if (expectedDeliveryTime) {
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
            description,
            origin,
            destination,
            expectedDelivery: expectedDelivery,
            senderName,
            recipientName,
            recipientEmail,
            packageContents,
            serviceType,
            recipientAddress,
            specialHandling,
            weight,
            history: history || [],
            statusLineColor: statusLineColor || '#2196F3',
            blinkingDotColor: blinkingDotColor || '#FFFFFF',
            isBlinking: typeof isBlinking === 'boolean' ? isBlinking : false,
            lastUpdated: new Date()
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
            // Construct a public URL for the attached file if it exists, now from Cloudinary
            const attachedFileUrl = tracking.attachedFileName ?
                cloudinary.url(tracking.attachedFileName, { secure: true, resource_type: 'raw' }) : // Use raw resource_type for non-image files
                null;

            res.json({
                ...tracking.toObject(),
                statusLineColor: tracking.statusLineColor || '#2196F3',
                blinkingDotColor: tracking.blinkingDotColor || '#FFFFFF',
                isBlinking: tracking.isBlinking,
                attachedFileUrl: attachedFileUrl
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
app.post('/api/admin/trackings/:id/history', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { date, time, location, description } = req.body;

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
        const tracking = await Tracking.findById(id);

        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        if (!tracking.history) {
            tracking.history = [];
        }

        const newHistoryItem = {
            timestamp: new Date(combinedTimestamp),
            location: location || '',
            description: description
        };

        tracking.history.push(newHistoryItem);
        tracking.history.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        tracking.lastUpdated = new Date();
        await tracking.save();

        res.status(201).json({ message: 'History event added successfully!', historyEvent: tracking.history[tracking.history.length -1] });
    } catch (error) {
        console.error('Error adding history event:', error);
        res.status(500).json({ message: 'Server error while adding history event.', error: error.message });
    }
});


// Edit a specific history event
app.put('/api/admin/trackings/:id/history/:historyId', authenticateAdmin, async (req, res) => {
    const { id, historyId } = req.params;
    const { date, time, location, description } = req.body;

    if (date === undefined && time === undefined && location === undefined && description === undefined) {
        return res.status(400).json({ message: 'At least one field (date, time, location, or description) is required to update a history event.' });
    }

    try {
        const tracking = await Tracking.findById(id);

        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

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

        res.json({ message: 'History event updated successfully!', historyEvent: historyEvent.toObject() });
    } catch (error) {
        console.error(`Error updating history event ${historyId} for tracking ID ${id}:`, error);
        if (error.name === 'CastError') {
            return res.status(400).json({ message: 'Invalid ID format for tracking or history event.' });
        }
        res.status(500).json({ message: 'Server error while updating history event.', error: error.message });
    }
});


// Admin Route to Update Tracking Details
app.put('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;

    try {
        let currentTracking = await Tracking.findById(id);

        if (!currentTracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        if (updateData.trackingId && updateData.trackingId !== currentTracking.trackingId) {
            const newTrackingId = updateData.trackingId;
            const existingTrackingWithNewId = await Tracking.findOne({ trackingId: newTrackingId });
            if (existingTrackingWithNewId && String(existingTrackingWithNewId._id) !== id) {
                return res.status(409).json({ message: 'New Tracking ID already exists. Please choose a different one.' });
            }
            console.log(`Tracking ID changed from (old): ${currentTracking.trackingId} to (new): ${newTrackingId}`);
            currentTracking.trackingId = newTrackingId;
        }

        Object.keys(updateData).forEach(key => {
            if (key === 'trackingId' || key === 'history' || key === '_id' || key === '__v' || updateData[key] === undefined) {
                return;
            }

            if (key === 'expectedDeliveryDate') {
                const effectiveDate = updateData.expectedDeliveryDate;
                const effectiveTime = updateData.expectedDeliveryTime || (currentTracking.expectedDelivery ? currentTracking.expectedDelivery.toISOString().split('T')[1].substring(0, 5) : '00:00');

                if (effectiveDate) {
                    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
                    if (!dateRegex.test(effectiveDate)) {
                        console.warn(`Invalid date format for expectedDeliveryDate: ${effectiveDate}`);
                        return;
                    }
                    const newExpectedDelivery = new Date(`${effectiveDate}T${effectiveTime}:00`);
                    if (!isNaN(newExpectedDelivery.getTime())) {
                        currentTracking.expectedDelivery = newExpectedDelivery;
                    } else {
                        console.warn(`Could not parse new expectedDelivery: ${effectiveDate} ${effectiveTime}`);
                    }
                }
            } else if (key === 'expectedDeliveryTime') {
                if (updateData.expectedDeliveryDate === undefined) {
                    const effectiveDate = currentTracking.expectedDelivery ? currentTracking.expectedDelivery.toISOString().split('T')[0] : (new Date().toISOString().split('T')[0]);
                    const effectiveTime = updateData.expectedDeliveryTime;

                    if (effectiveTime) {
                        const timeRegex = /^(?:2[0-3]|[01]?[0-9]):[0-5][0-9]$/;
                        if (!timeRegex.test(effectiveTime)) {
                            console.warn(`Invalid time format for expectedDeliveryTime: ${effectiveTime}`);
                            return;
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
    const { id, historyId } = req.params;

    try {
        const tracking = await Tracking.findById(id);
        if (!tracking) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        const historyLengthBeforePull = tracking.history.length;
        tracking.history.pull({ _id: historyId });

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
app.delete('/api/admin/trackings/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const trackingToDelete = await Tracking.findById(id);
        if (!trackingToDelete) {
            return res.status(404).json({ message: 'Tracking record not found.' });
        }

        // If an attached file exists, delete it from Cloudinary
        if (trackingToDelete.attachedFileName) {
            await cloudinary.uploader.destroy(trackingToDelete.attachedFileName); // Delete by public_id
        }

        const result = await Tracking.deleteOne({ _id: id });
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
// To use this, uncomment the section, make a POST request, then re-comment for security.
/*
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
*/

// --- IMPORTANT: Remove static HTML routes (your frontend serves these) ---
// app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
// app.get('/admin_login.html', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin_login.html')); });
// app.get('/admin_dashboard.html', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html')); });
// app.get('/track_details.html', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'track_details.html')); });


// --- Universal 404 handler (important for serverless) ---
// This should only handle paths that *start* with /api or similar base path
// For unmatched paths in Netlify, it will typically return a 404 from Netlify itself
app.use((req, res, next) => {
    res.status(404).json({ message: 'API Endpoint not found.' });
});

// Error handling middleware (should be last)
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.statusCode || 500).json({
        message: err.message || 'An unexpected error occurred on the server.',
        error: process.env.NODE_ENV === 'production' ? {} : err.stack
    });
});


// --- Export the Express app wrapped for serverless ---
module.exports.handler = serverless(app);

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // For file uploads
// const path = require('path');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// const fs = require('fs');

const SECRET_KEY = process.env.JWT_SECRET || 'super_secret_owner_key'; // CHANGE THIS IN PRODUCTION

// 1. SETUP EXPRESS APP
const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration
const corsOptions = {
    origin: '*', 
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));
 // Required for parsing form-data text fields

// Debug Logger
app.use((req, res, next) => {
    console.log(`[${req.method}] ${req.url}`);
    next();
});

console.log('==== ENV DEBUG START ====');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('PORT:', PORT);
console.log('==== ENV DEBUG END ====');

// ==========================================
// 2. FILE UPLOAD SETUP (Multer)
// ==========================================

// Ensure 'uploads' folder exists
// const uploadDir = './uploads';
// if (!fs.existsSync(uploadDir)){
//     fs.mkdirSync(uploadDir);
// }

// Configure Storage
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'attendance_app',
    allowed_formats: ['jpg', 'jpeg', 'png'],
  },
});


const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
});


// Make the 'uploads' folder public so frontend can display images
// app.use('/uploads', express.static('uploads')); 


// ==========================================
// 3. DATABASE CONNECTION
// ==========================================
const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
        host: process.env.DB_HOST,
        dialect: 'mysql', // Change to 'postgres' if needed
        logging: false
    }
);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ==========================================
// 4. DEFINE MODELS
// ==========================================

// --- Employee Model ---
const Employee = sequelize.define('Employee', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    full_name: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: true, unique: true },
    otp: { type: DataTypes.STRING },
    profile_image: { type: DataTypes.STRING, allowNull: true }, // Stores image path
    dob: { type: DataTypes.DATEONLY },
    joining_date: { type: DataTypes.DATEONLY, allowNull: false },
    employment_type: { type: DataTypes.ENUM('hourly', 'daily', 'weekly'), allowNull: false },
    work_rate: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
    position: DataTypes.STRING,
    department: DataTypes.STRING,
    shift: { type: DataTypes.ENUM('morning', 'evening', 'night', 'custom') },
    phone: DataTypes.STRING,
    allowed_leaves: { type: DataTypes.INTEGER, defaultValue: 12 },
    taken_leaves: { type: DataTypes.INTEGER, defaultValue: 0 },
    status: { type: DataTypes.ENUM('active', 'on-leave', 'inactive'), defaultValue: 'active' }
}, {
    tableName: 'employees',
    underscored: true,
    timestamps: true,
    updatedAt: false,
    createdAt: 'created_at'
});

// --- Attendance Model ---
const Attendance = sequelize.define('Attendance', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    employee_id: { type: DataTypes.UUID, allowNull: false },
    date: { type: DataTypes.DATEONLY, allowNull: false, defaultValue: DataTypes.NOW },
    sign_in: { type: DataTypes.DATE },
    sign_out: { type: DataTypes.DATE },
    clock_in_image: { type: DataTypes.STRING }, // Selfie path
    clock_out_image: { type: DataTypes.STRING }, // Selfie path
    status: { type: DataTypes.ENUM('present', 'late', 'absent', 'on-leave'), defaultValue: 'present' },
    total_hours: { type: DataTypes.DECIMAL(5, 2) }
}, {
    tableName: 'attendance',
    timestamps: true,
    updatedAt: false,
    createdAt: 'created_at'
});

// --- Break Record Model ---
const BreakRecord = sequelize.define('BreakRecord', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    employee_id: { type: DataTypes.UUID, allowNull: false },
    date: { type: DataTypes.DATEONLY, defaultValue: DataTypes.NOW },
    start_time: { type: DataTypes.DATE, allowNull: false },
    end_time: { type: DataTypes.DATE },
    duration_minutes: { type: DataTypes.INTEGER, defaultValue: 0 },
    type: { type: DataTypes.STRING, defaultValue: 'General' }
}, {
    tableName: 'break_records',
    timestamps: true,
    updatedAt: false,
    createdAt: 'created_at',
    underscored: true
});

// --- Other Models ---
const LeaveRequest = sequelize.define('LeaveRequest', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    employee_id: { type: DataTypes.UUID, allowNull: false },
    leave_type: { type: DataTypes.ENUM('planned', 'happy', 'medical'), allowNull: false },
    start_date: { type: DataTypes.DATEONLY, allowNull: false },
    end_date: { type: DataTypes.DATEONLY, allowNull: false },
    reason: { type: DataTypes.TEXT },
    status: { type: DataTypes.ENUM('pending', 'approved', 'rejected'), defaultValue: 'pending' }
}, { tableName: 'leave_requests', timestamps: true, updatedAt: false, createdAt: 'created_at' });

const Holiday = sequelize.define('Holiday', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    date: { type: DataTypes.DATEONLY, allowNull: false },
    description: { type: DataTypes.TEXT }
}, { tableName: 'holidays', timestamps: true, updatedAt: false, createdAt: 'created_at' });

const NewMember = sequelize.define('NewMember', {
    id: { type: DataTypes.CHAR(36), primaryKey: true, defaultValue: DataTypes.UUIDV4 },
    name: { type: DataTypes.STRING, allowNull: false },
    number: { type: DataTypes.STRING, allowNull: false }
}, { tableName: 'new_member', timestamps: true, updatedAt: false, createdAt: 'created_at' });

const Admin = sequelize.define('Admin', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false }
}, { tableName: 'admins', timestamps: false });

// ==========================================
// 5. RELATIONSHIPS
// ==========================================
Employee.hasMany(Attendance, { foreignKey: 'employee_id' });
Attendance.belongsTo(Employee, { foreignKey: 'employee_id' });

Employee.hasMany(LeaveRequest, { foreignKey: 'employee_id' });
LeaveRequest.belongsTo(Employee, { foreignKey: 'employee_id' });

Employee.hasMany(BreakRecord, { foreignKey: 'employee_id' });
BreakRecord.belongsTo(Employee, { foreignKey: 'employee_id' });

// --- Alert Model (For Out-of-Range Warnings) ---
const Alert = sequelize.define('Alert', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    employee_id: { type: DataTypes.UUID, allowNull: false },
    type: { type: DataTypes.ENUM('out_of_range', 'late', 'absent'), defaultValue: 'out_of_range' },
    message: { type: DataTypes.STRING }, // e.g. "Out for 15 mins"
    minutes_out: { type: DataTypes.INTEGER, defaultValue: 0 },
    is_read: { type: DataTypes.BOOLEAN, defaultValue: false } // To show unread notifications
}, {
    tableName: 'alerts',
    timestamps: true,
    updatedAt: false,
    createdAt: 'created_at'
});

// Relationship
Employee.hasMany(Alert, { foreignKey: 'employee_id' });
Alert.belongsTo(Employee, { foreignKey: 'employee_id' });
// ==========================================
// 6. MIDDLEWARE (Auth)
// ==========================================
const verifyOwner = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'No token provided' });

    const cleanToken = token.startsWith('Bearer ') ? token.slice(7, token.length) : token;

    jwt.verify(cleanToken, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Unauthorized: Invalid Token' });
        req.adminId = decoded.id;
        next();
    });
};

// ==========================================
// 7. API ROUTES
// ==========================================

// --- AUTH & OTP ---
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { name, phone, email } = req.body;
        if (!name || !phone || !email) return res.status(400).json({ error: 'Missing details.' });

        const user = await Employee.findOne({ where: { phone, email, full_name: name } });
        if (!user) return res.status(404).json({ error: 'User details do not match.' });

        const otp = '52050'; // Hardcoded for testing
        user.otp = otp;
        await user.save();

        console.log(`>> TEST OTP for ${user.full_name}: ${otp}`);
        res.json({ message: 'OTP sent successfully!' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        const user = await Employee.findOne({ where: { phone } });
        
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (String(user.otp) !== String(otp)) return res.status(400).json({ error: 'Invalid OTP' });

        user.otp = null;
        await user.save();
        res.json({ message: 'Login successful', user });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/register', async (req, res) => { // Owner Register
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const admin = await Admin.create({ email, password: hashedPassword });
        res.json({ message: 'Owner account created', adminId: admin.id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => { // Owner Login
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ where: { email } });
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const token = jwt.sign({ id: admin.id, role: 'owner' }, SECRET_KEY, { expiresIn: '12h' });
        res.json({ message: 'Login successful', token });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- EMPLOYEES (With Image Upload) ---
app.post('/api/employees', upload.single('profile_image'), async (req, res) => {
    try {
        const employeeData = req.body;
        if (req.file) {
            employeeData.profile_image = req.file.path;
        }
        const newEmp = await Employee.create(employeeData);
        res.status(201).json({ message: 'Created', data: newEmp });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/employees', async (req, res) => {
    try {
        const employees = await Employee.findAll({ order: [['created_at', 'DESC']] });
        res.json(employees);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/employees/verify/:phone', async (req, res) => {
    const employee = await Employee.findOne({ where: { phone: req.params.phone } });
    employee ? res.json(employee) : res.status(404).json({ error: 'Not found' });
});

app.put('/api/employees/:id', verifyOwner, async (req, res) => {
    try {
        const [updated] = await Employee.update(req.body, { where: { id: req.params.id } });
        if (updated) {
            const emp = await Employee.findByPk(req.params.id);
            res.json({ message: 'Updated', data: emp });
        } else { res.status(404).json({ error: 'Not found' }); }
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/employees/:id', verifyOwner, async (req, res) => {
    try {
        const deleted = await Employee.destroy({ where: { id: req.params.id } });
        deleted ? res.json({ message: 'Deleted' }) : res.status(404).json({ error: 'Not found' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});


// --- ATTENDANCE (With Selfie Upload) ---
// UPDATED CLOCK-IN ROUTE (Checks if Employee exists first)
app.post('/api/attendance/clock-in', upload.single('image'), async (req, res) => {
    try {
        console.log("--- CLOCK IN DEBUG ---");
        console.log("1. Body Received:", req.body);
        console.log("2. File Received:", req.file ? req.file.filename : "No File");

        const { employee_id } = req.body;

        // 1. VALIDATION: Check if ID was actually sent
        if (!employee_id || employee_id === 'undefined') {
            return res.status(400).json({ error: 'Employee ID is missing from request body.' });
        }

        // 2. INTEGRITY CHECK: Check if this Employee actually exists in DB
        const validEmployee = await Employee.findByPk(employee_id);
        if (!validEmployee) {
            return res.status(404).json({ error: 'This Employee ID does not exist in the database.' });
        }

        // 3. DUPLICATE CHECK: Check for existing attendance today
        // 3. DUPLICATE CHECK (FIXED FOR DATEONLY)
const today = new Date().toISOString().split('T')[0];

const existing = await Attendance.findOne({
    where: {
        employee_id,
        date: today
    }
});

if (existing) {
    return res.status(400).json({ error: 'Already clocked in for today.' });
}

        // 4. CREATE RECORD
        const newRecord = await Attendance.create({
            employee_id,
            date: new Date(),
            sign_in: new Date(),
            status: 'present',
            clock_in_image: req.file ? `/uploads/${req.file.filename}` : null
        });

        console.log(">> Success: Clock In Recorded");
        res.status(201).json({ message: 'Clocked In', data: newRecord });

    } catch (error) {
        console.error(">> ERROR:", error);
        res.status(500).json({ error: error.message }); 
    }
});

// --- IMPROVED CLOCK OUT ROUTE ---
app.post('/api/attendance/clock-out', upload.single('image'), async (req, res) => {
  try {
    const { employee_id } = req.body;

    if (!employee_id) {
      return res.status(400).json({ error: 'Employee ID is missing.' });
    }

    const today = new Date().toISOString().split('T')[0];

    const record = await Attendance.findOne({
      where: {
        employee_id,
        date: today,
        sign_out: null
      }
    });

    if (!record) {
      return res.status(404).json({ error: 'You are not clocked in!' });
    }

    const now = new Date();
    const diffMs = now - new Date(record.sign_in);
    const totalHours = (diffMs / (1000 * 60 * 60)).toFixed(2);

    record.sign_out = now;
    record.total_hours = totalHours;

    if (req.file) {
      record.clock_out_image = `/uploads/${req.file.filename}`;
    }

    await record.save();

    console.log(`Clock-out success: ${totalHours} hours`);

    res.json({
      message: 'Clocked Out',
      total_hours: totalHours,
      data: record
    });

  } catch (error) {
    console.error('Clock-out Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attendance', verifyOwner, async (req, res) => {
    try {
        const logs = await Attendance.findAll({
            include: [{ model: Employee, attributes: ['full_name', 'position', 'profile_image'] }],
            order: [['date', 'DESC'], ['sign_in', 'DESC']]
        });
        res.json(logs);
    } catch (error) { res.status(500).json({ error: error.message }); }
});


// --- BREAKS ---
app.post('/api/attendance/break/start', async (req, res) => {
    try {
        const { employee_id, type } = req.body;
        const activeBreak = await BreakRecord.findOne({ where: { employee_id, date: new Date(), end_time: null } });
        if (activeBreak) return res.status(400).json({ error: 'Already on a break!' });

        const newBreak = await BreakRecord.create({
            employee_id,
            start_time: new Date(),
            date: new Date(),
            type: type || 'General'
        });
        res.status(201).json({ message: 'Break started', data: newBreak });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/attendance/break/end', async (req, res) => {
    try {
        const { employee_id } = req.body;
        const activeBreak = await BreakRecord.findOne({ where: { employee_id, date: new Date(), end_time: null } });
        if (!activeBreak) return res.status(404).json({ error: 'No active break found' });

        const now = new Date();
        const minutes = Math.floor((now - new Date(activeBreak.start_time)) / 60000); 

        activeBreak.end_time = now;
        activeBreak.duration_minutes = minutes;
        await activeBreak.save();

        res.json({ message: 'Break ended', duration_minutes: minutes, data: activeBreak });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/breaks', async (req, res) => { // Public (No VerifyOwner)
    try {
        const breaks = await BreakRecord.findAll({
            include: [{ model: Employee, attributes: ['full_name'] }],
            order: [['start_time', 'DESC']]
        });
        res.json(breaks);
    } catch (error) { res.status(500).json({ error: error.message }); }
});


// --- LEAVES, HOLIDAYS, MEMBERS (Standard) ---
app.post('/api/leaves', async (req, res) => { /* ... Same as before ... */
    try {
        const { employee_id, leave_type, start_date, end_date, reason } = req.body;
        if (new Date(end_date) < new Date(start_date)) return res.status(400).json({ error: 'Invalid dates' });
        const newLeave = await LeaveRequest.create({ employee_id, leave_type, start_date, end_date, reason });
        res.status(201).json({ message: 'Submitted', data: newLeave });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/leaves', async (req, res) => {
    const requests = await LeaveRequest.findAll({ include: [{ model: Employee, attributes: ['full_name'] }], order: [['created_at', 'DESC']] });
    res.json(requests);
});

app.put('/api/leaves/:id/status', async (req, res) => {
    const { id } = req.params; const { status } = req.body;
    const leave = await LeaveRequest.findByPk(id);
    if (!leave) return res.status(404).json({ error: 'Not found' });
    leave.status = status; await leave.save();
    res.json({ message: `Status updated to ${status}` });
});

app.get('/api/holidays', async (req, res) => {
    const holidays = await Holiday.findAll({ order: [['date', 'ASC']] });
    res.json(holidays);
});
app.post('/api/holidays', verifyOwner, async (req, res) => {
    const newHoliday = await Holiday.create(req.body);
    res.status(201).json(newHoliday);
});

app.get('/api/members', async (req, res) => {
    const members = await NewMember.findAll({ order: [['created_at', 'DESC']] });
    res.json(members);
});
app.post('/api/members', async (req, res) => {
    const member = await NewMember.create(req.body);
    res.status(201).json(member);
});
app.delete('/api/members/:id', verifyOwner, async (req, res) => {
    await NewMember.destroy({ where: { id: req.params.id } });
    res.json({ message: 'Deleted' });
});
app.get('/api/attendance/employee/:employeeId', async (req, res) => {
    try {
        const logs = await Attendance.findAll({
            where: { employee_id: req.params.employeeId },
            order: [['date', 'DESC']]
        });
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// --- CHECK CURRENT STATUS ROUTE ---
// --- CHECK CURRENT STATUS ROUTE (UPDATED) ---
// --- CHECK STATUS ROUTE ---
// --- ROBUST STATUS CHECK (Fixes Timezone/Date Issues) ---
// --- ROBUST STATUS CHECK (Fixed for IST Timezone) ---
app.get('/api/attendance/status/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Get the LAST attendance record
        const lastRecord = await Attendance.findOne({
            where: { employee_id: id },
            order: [['created_at', 'DESC']] 
        });

        if (!lastRecord) {
            return res.json({ status: 'out' });
        }

        // 2. CONVERT DATES TO INDIA TIME (IST) BEFORE COMPARING
        // This ensures 9 AM IST and 6 PM IST are treated as the "Same Day"
        const options = { timeZone: 'Asia/Kolkata', year: 'numeric', month: 'numeric', day: 'numeric' };
        
        const recordDate = new Date(lastRecord.created_at).toLocaleDateString('en-IN', options);
        const serverDate = new Date().toLocaleDateString('en-IN', options);

        // Debug Logs (Check these in Render logs if it fails)
        console.log(`Record Date (IST): ${recordDate} | Server Date (IST): ${serverDate}`);

        // 3. Compare Dates
        if (recordDate !== serverDate) {
            // The last record is from a previous day (Yesterday)
            return res.json({ status: 'out' });
        }

        // 4. Determine Status
        if (lastRecord.sign_out) {
            return res.json({ status: 'completed' }); // Shift Over
        } else {
            // Check Break
            const activeBreak = await BreakRecord.findOne({ 
                where: { employee_id: id, end_time: null } 
            });

            if (activeBreak) {
                return res.json({ status: 'break', start_time: activeBreak.start_time });
            }

            return res.json({ status: 'in', start_time: lastRecord.sign_in });
        }

    } catch (error) {
        console.error("Status Error:", error);
        res.status(500).json({ error: error.message });
    }
});
// --- ADMIN ALERT ROUTE (UPDATED) ---
app.post('/api/admin/alert/out-of-range', async (req, res) => {
    try {
        const { employee_id, minutes } = req.body;
        
        const employee = await Employee.findByPk(employee_id);
        if (!employee) return res.status(404).json({ error: 'User not found' });

        // 1. SAVE TO DATABASE (So Admin sees it later)
        await Alert.create({
            employee_id,
            type: 'out_of_range',
            minutes_out: minutes,
            message: `${employee.full_name} was out of range for ${minutes} mins.`
        });

        console.log(`⚠️ ALERT SAVED: ${employee.full_name} (${minutes}m)`);

        res.json({ message: 'Admin Notified & Saved' });
    } catch (error) {
        console.error("Alert Error:", error);
        res.status(500).json({ error: error.message });
    }
});
// --- GET ALL ALERTS (For Admin Dashboard) ---
app.get('/api/admin/alerts', verifyOwner, async (req, res) => {
    try {
        const alerts = await Alert.findAll({
            include: [{ model: Employee, attributes: ['full_name', 'profile_image'] }],
            order: [['created_at', 'DESC']]
        });
        res.json(alerts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// ==========================================
// 8. START SERVER
// ==========================================
async function startServer() {
    console.log(">> 1. Starting App...");
    try {
        await sequelize.authenticate();
        console.log(">> 2. Database Connection Established!");
        
        // 'alter: true' adds the new columns (profile_image, clock_in_image) automatically
        await sequelize.sync({ alter: true }); 
        console.log(">> 3. Database Synced.");

        app.listen(PORT, () => {
            console.log(`>> 4. Server is live on port ${PORT}`);
        });

    } catch (err) {
        console.error(">> ❌ CRITICAL DATABASE ERROR:", err.message);
    }
}

startServer();

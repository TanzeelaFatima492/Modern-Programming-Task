const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const Customer = require('./models/Customer');
const Admin = require('./models/Admin');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from Views folder
app.use(express.static(path.join(__dirname, 'Views')));

// MongoDB connection
const MONGODB_URI = 'mongodb://localhost:27017/customer_management';

mongoose.connect(MONGODB_URI);

const db = mongoose.connection;
db.on('error', console.error.bind(console, '❌ MongoDB connection error:'));
db.once('open', async () => {
    console.log('✅ Connected to MongoDB successfully');
    console.log('📊 Database: customer_management');
    
    // Check if collections exist
    try {
        const collections = await mongoose.connection.db.listCollections().toArray();
        const collectionNames = collections.map(c => c.name);
        
        console.log('📁 Available collections:', collectionNames.join(', ') || 'No collections yet');
        
        if (!collectionNames.includes('customers')) {
            console.log('⚠️ Customers collection will be created when you add first customer');
        }
        if (!collectionNames.includes('admins')) {
            console.log('⚠️ Admins collection will be created when you add first admin');
        }
    } catch (err) {
        console.log('📁 Collections will be created automatically when data is added');
    }
});

// Initialize sample data if collections are empty
async function initializeSampleData() {
    try {
        // Initialize Customers
        const customerCount = await Customer.countDocuments();
        if (customerCount === 0) {
            const sampleCustomers = [
                {
                    customerId: "CUST001",
                    firstName: "John",
                    lastName: "Doe",
                    email: "john@example.com",
                    phone: "+1 (555) 123-4567",
                    membership: "Gold",
                    totalSpent: 1250.00,
                    orders: 15,
                    rating: 4.5,
                    lastActive: new Date().toISOString().split('T')[0],
                    joinDate: new Date().toISOString().split('T')[0],
                    address: { street: "123 Main St", city: "New York", zipCode: "10001" }
                },
                {
                    customerId: "CUST002",
                    firstName: "Jane",
                    lastName: "Smith",
                    email: "jane@example.com",
                    phone: "+1 (555) 234-5678",
                    membership: "Platinum",
                    totalSpent: 3450.00,
                    orders: 28,
                    rating: 4.8,
                    lastActive: new Date().toISOString().split('T')[0],
                    joinDate: new Date().toISOString().split('T')[0],
                    address: { street: "456 Oak Ave", city: "Los Angeles", zipCode: "90001" }
                },
                {
                    customerId: "CUST003",
                    firstName: "Mike",
                    lastName: "Johnson",
                    email: "mike@example.com",
                    phone: "+1 (555) 345-6789",
                    membership: "Silver",
                    totalSpent: 450.00,
                    orders: 8,
                    rating: 4.2,
                    lastActive: new Date().toISOString().split('T')[0],
                    joinDate: new Date().toISOString().split('T')[0],
                    address: { street: "789 Pine Rd", city: "Chicago", zipCode: "60601" }
                }
            ];
            await Customer.insertMany(sampleCustomers);
            console.log('📝 Sample customer data inserted successfully');
        }

        // Initialize Admins
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            const sampleAdmins = [
                {
                    adminId: "ADMIN001",
                    name: "John Smith",
                    email: "john.smith@example.com",
                    role: "Super Admin",
                    phone: "+1 (555) 123-4567",
                    department: "IT",
                    managedCustomers: 145,
                    joinDate: new Date().toISOString().split('T')[0],
                    lastActive: new Date().toISOString().split('T')[0],
                    status: "Active"
                },
                {
                    adminId: "ADMIN002",
                    name: "Sarah Johnson",
                    email: "sarah.j@example.com",
                    role: "Admin",
                    phone: "+1 (555) 234-5678",
                    department: "Sales",
                    managedCustomers: 98,
                    joinDate: new Date().toISOString().split('T')[0],
                    lastActive: new Date().toISOString().split('T')[0],
                    status: "Active"
                },
                {
                    adminId: "ADMIN003",
                    name: "Mike Williams",
                    email: "mike.w@example.com",
                    role: "Moderator",
                    phone: "+1 (555) 345-6789",
                    department: "Support",
                    managedCustomers: 67,
                    joinDate: new Date().toISOString().split('T')[0],
                    lastActive: new Date().toISOString().split('T')[0],
                    status: "Active"
                }
            ];
            await Admin.insertMany(sampleAdmins);
            console.log('📝 Sample admin data inserted successfully');
        }
    } catch (error) {
        console.error('Error initializing sample data:', error);
    }
}

// ============= CUSTOMER API ROUTES =============

// Get all customers
app.get('/api/customers', async (req, res) => {
    try {
        const customers = await Customer.find().sort({ createdAt: -1 });
        res.json({ success: true, data: customers });
    } catch (error) {
        console.error('Error fetching customers:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get single customer
app.get('/api/customers/:customerId', async (req, res) => {
    try {
        const customer = await Customer.findOne({ customerId: req.params.customerId });
        if (customer) {
            res.json({ success: true, data: customer });
        } else {
            res.status(404).json({ success: false, error: 'Customer not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add new customer
app.post('/api/customers', async (req, res) => {
    try {
        const existingCustomer = await Customer.findOne({ customerId: req.body.customerId });
        if (existingCustomer) {
            return res.status(400).json({ success: false, error: 'Customer ID already exists' });
        }
        
        const existingEmail = await Customer.findOne({ email: req.body.email });
        if (existingEmail) {
            return res.status(400).json({ success: false, error: 'Email already exists' });
        }
        
        const customer = new Customer(req.body);
        await customer.save();
        res.json({ success: true, data: customer, message: 'Customer added successfully' });
    } catch (error) {
        console.error('Error adding customer:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update customer
app.put('/api/customers/:customerId', async (req, res) => {
    try {
        const customer = await Customer.findOneAndUpdate(
            { customerId: req.params.customerId },
            req.body,
            { new: true, runValidators: true }
        );
        if (customer) {
            res.json({ success: true, data: customer, message: 'Customer updated successfully' });
        } else {
            res.status(404).json({ success: false, error: 'Customer not found' });
        }
    } catch (error) {
        console.error('Error updating customer:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete customer
app.delete('/api/customers/:customerId', async (req, res) => {
    try {
        const result = await Customer.findOneAndDelete({ customerId: req.params.customerId });
        if (result) {
            res.json({ success: true, message: 'Customer deleted successfully' });
        } else {
            res.status(404).json({ success: false, error: 'Customer not found' });
        }
    } catch (error) {
        console.error('Error deleting customer:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============= ADMIN API ROUTES =============

// Get all admins
app.get('/api/admins', async (req, res) => {
    try {
        const admins = await Admin.find().sort({ createdAt: -1 });
        res.json({ success: true, data: admins });
    } catch (error) {
        console.error('Error fetching admins:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get single admin
app.get('/api/admins/:adminId', async (req, res) => {
    try {
        const admin = await Admin.findOne({ adminId: req.params.adminId });
        if (admin) {
            res.json({ success: true, data: admin });
        } else {
            res.status(404).json({ success: false, error: 'Admin not found' });
        }
    } catch (error) {
        console.error('Error fetching admin:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add new admin
app.post('/api/admins', async (req, res) => {
    try {
        const existingAdmin = await Admin.findOne({ email: req.body.email });
        if (existingAdmin) {
            return res.status(400).json({ success: false, error: 'Email already exists' });
        }
        
        const existingId = await Admin.findOne({ adminId: req.body.adminId });
        if (existingId) {
            return res.status(400).json({ success: false, error: 'Admin ID already exists' });
        }
        
        const admin = new Admin(req.body);
        await admin.save();
        res.json({ success: true, data: admin, message: 'Admin added successfully' });
    } catch (error) {
        console.error('Error adding admin:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update admin
app.put('/api/admins/:adminId', async (req, res) => {
    try {
        const admin = await Admin.findOneAndUpdate(
            { adminId: req.params.adminId },
            req.body,
            { new: true, runValidators: true }
        );
        if (admin) {
            res.json({ success: true, data: admin, message: 'Admin updated successfully' });
        } else {
            res.status(404).json({ success: false, error: 'Admin not found' });
        }
    } catch (error) {
        console.error('Error updating admin:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete admin
app.delete('/api/admins/:adminId', async (req, res) => {
    try {
        const result = await Admin.findOneAndDelete({ adminId: req.params.adminId });
        if (result) {
            res.json({ success: true, message: 'Admin deleted successfully' });
        } else {
            res.status(404).json({ success: false, error: 'Admin not found' });
        }
    } catch (error) {
        console.error('Error deleting admin:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============= STATS API =============

// Get statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalCustomers = await Customer.countDocuments();
        const totalAdmins = await Admin.countDocuments();
        const revenueResult = await Customer.aggregate([
            { $group: { _id: null, total: { $sum: "$totalSpent" } } }
        ]);
        const goldMembers = await Customer.countDocuments({ membership: 'Gold' });
        const platinumMembers = await Customer.countDocuments({ membership: 'Platinum' });
        const silverMembers = await Customer.countDocuments({ membership: 'Silver' });
        
        res.json({
            success: true,
            data: {
                totalCustomers,
                totalAdmins,
                goldMembers,
                platinumMembers,
                silverMembers,
                totalRevenue: revenueResult[0]?.total || 0,
                averageSpending: totalCustomers > 0 ? (revenueResult[0]?.total || 0) / totalCustomers : 0
            }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============= TEST DATABASE ROUTE =============

// Test route to check database connection
app.get('/api/test-db', async (req, res) => {
    try {
        const customers = await Customer.find();
        const admins = await Admin.find();
        
        res.json({
            success: true,
            message: 'Database connection successful',
            stats: {
                customersCount: customers.length,
                adminsCount: admins.length,
                databaseName: mongoose.connection.db.databaseName
            },
            sampleCustomer: customers[0] || null,
            sampleAdmin: admins[0] || null
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============= SERVE HTML PAGES =============

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Views', 'index.html'));
});

app.get('/customers', (req, res) => {
    res.sendFile(path.join(__dirname, 'Views', 'customers.html'));
});

app.get('/admins', (req, res) => {
    res.sendFile(path.join(__dirname, 'Views', 'admins.html'));
});

// ============= START SERVER =============

async function startServer() {
    try {
        await initializeSampleData();
        
        // Try different ports if the default is busy
        const tryPorts = [3001, 3002, 3003, 3004, 3005, 8080, 8081];
        let serverStarted = false;
        
        for (const port of tryPorts) {
            try {
                await new Promise((resolve, reject) => {
                    const server = app.listen(port, () => {
                        console.log(`\n🚀 Server is running on port ${port}!`);
                        console.log(`📱 Access the application at: http://localhost:${port}`);
                        console.log(`👥 Customers page: http://localhost:${port}/customers`);
                        console.log(`👨‍💼 Admins page: http://localhost:${port}/admins`);
                        console.log(`✅ MongoDB connected successfully\n`);
                        console.log(`📊 You can view your data in MongoDB Compass:`);
                        console.log(`   Connection: mongodb://localhost:27017`);
                        console.log(`   Database: customer_management`);
                        console.log(`   Collections: customers, admins\n`);
                        console.log(`🔍 Test database: http://localhost:${port}/api/test-db\n`);
                        serverStarted = true;
                        resolve();
                    });
                    server.on('error', reject);
                });
                break;
            } catch (err) {
                if (err.code === 'EADDRINUSE') {
                    console.log(`Port ${port} is busy, trying next port...`);
                    continue;
                }
                throw err;
            }
        }
        
        if (!serverStarted) {
            console.error('❌ No available ports found. Please close some applications.');
        }
    } catch (error) {
        console.error('Failed to start server:', error);
    }
}

startServer();
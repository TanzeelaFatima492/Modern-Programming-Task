const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
const MONGODB_URI = 'mongodb://localhost:27017';
const DB_NAME = 'EcommerceDB';

let db;
let customersCollection;
let adminsCollection;

// Connect to MongoDB
async function connectDB() {
    try {
        const client = await MongoClient.connect(MONGODB_URI);
        db = client.db(DB_NAME);
        customersCollection = db.collection('customers');
        adminsCollection = db.collection('admins');
        console.log('✅ Connected to MongoDB Database: EcommerceDB');
        
        // Create sample data if collections are empty
        await initializeData();
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error);
        console.log('\n⚠️  Make sure MongoDB is running!');
        console.log('Start MongoDB with: net start MongoDB (as Administrator)\n');
    }
}

async function initializeData() {
    // Check if customers exist
    const customerCount = await customersCollection.countDocuments();
    if (customerCount === 0) {
        console.log('📝 Adding sample customer data...');
        await customersCollection.insertMany([
            {
                customerId: "CUST001",
                firstName: "John",
                lastName: "Doe",
                email: "john@gmail.com",
                phone: "+1234567890",
                address: {
                    street: "123 Main St",
                    city: "New York",
                    zipCode: "10001"
                },
                membership: "Gold",
                totalSpent: 1250.50,
                createdAt: new Date().toISOString().split('T')[0]
            },
            {
                customerId: "CUST002",
                firstName: "Emma",
                lastName: "Wilson",
                email: "emma@gmail.com",
                phone: "+1987654321",
                address: {
                    street: "456 Oak Ave",
                    city: "Los Angeles",
                    zipCode: "90001"
                },
                membership: "Silver",
                totalSpent: 450.75,
                createdAt: new Date().toISOString().split('T')[0]
            },
            {
                customerId: "CUST003",
                firstName: "Mike",
                lastName: "Brown",
                email: "mike@gmail.com",
                phone: "+1122334455",
                address: {
                    street: "789 Pine Rd",
                    city: "Chicago",
                    zipCode: "60601"
                },
                membership: "Platinum",
                totalSpent: 3500.00,
                createdAt: new Date().toISOString().split('T')[0]
            }
        ]);
        console.log('✅ Sample customers added!');
    }
    
    const adminCount = await adminsCollection.countDocuments();
    if (adminCount === 0) {
        console.log('📝 Adding sample admin data...');
        await adminsCollection.insertMany([
            {
                adminId: "ADM001",
                firstName: "Alice",
                lastName: "Johnson",
                email: "alice@admin.com",
                role: "Super Admin",
                permissions: ["read", "write", "delete", "manage_users"],
                createdAt: new Date().toISOString().split('T')[0]
            },
            {
                adminId: "ADM002",
                firstName: "Bob",
                lastName: "Smith",
                email: "bob@admin.com",
                role: "Support Admin",
                permissions: ["read", "write"],
                createdAt: new Date().toISOString().split('T')[0]
            }
        ]);
        console.log('✅ Sample admins added!');
    }
}

// Serve HTML files
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin & Customer System</title>
            <style>
                body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; margin: 0; }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { text-align: center; color: white; margin-bottom: 40px; }
                .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-bottom: 40px; }
                .card { background: white; border-radius: 15px; padding: 30px; text-align: center; cursor: pointer; transition: transform 0.3s; }
                .card:hover { transform: translateY(-5px); }
                .card-icon { font-size: 4em; margin-bottom: 10px; }
                .btn { display: inline-block; padding: 10px 25px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 25px; margin-top: 15px; }
                .stats { background: white; border-radius: 15px; padding: 30px; }
                .stats h3 { text-align: center; margin-bottom: 20px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
                .stat-box { text-align: center; padding: 15px; background: #f0f0f0; border-radius: 10px; }
                .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🏢 Admin & Customer Management System</h1>
                <div class="cards">
                    <div class="card">
                        <div class="card-icon">👥</div>
                        <h2>Manage Customers</h2>
                        <p>View, add, edit, and delete customer records</p>
                        <a href="/customers" class="btn">View Customers →</a>
                    </div>
                    <div class="card">
                        <div class="card-icon">👨‍💼</div>
                        <h2>Manage Admins</h2>
                        <p>View system administrators</p>
                        <a href="/admins" class="btn">View Admins →</a>
                    </div>
                    <div class="card">
                        <div class="card-icon">📊</div>
                        <h2>Dashboard</h2>
                        <p>View system statistics and analytics</p>
                        <a href="/dashboard" class="btn">Go to Dashboard →</a>
                    </div>
                </div>
                <div class="stats">
                    <h3>📈 Live Statistics</h3>
                    <div class="stats-grid" id="stats">
                        <div class="stat-box">
                            <div class="stat-number" id="totalCustomers">-</div>
                            <div>Total Customers</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number" id="totalAdmins">-</div>
                            <div>Total Admins</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number" id="goldMembers">-</div>
                            <div>Gold Members</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number" id="totalRevenue">-</div>
                            <div>Total Revenue</div>
                        </div>
                    </div>
                </div>
            </div>
            <script>
                async function loadStats() {
                    try {
                        const response = await fetch('/api/stats');
                        const data = await response.json();
                        if(data.success) {
                            document.getElementById('totalCustomers').textContent = data.data.totalCustomers;
                            document.getElementById('totalAdmins').textContent = data.data.totalAdmins;
                            document.getElementById('goldMembers').textContent = data.data.goldMembers;
                            document.getElementById('totalRevenue').textContent = '$' + data.data.totalRevenue.toFixed(2);
                        }
                    } catch(error) {
                        console.error('Error:', error);
                    }
                }
                loadStats();
                setInterval(loadStats, 5000);
            </script>
        </body>
        </html>
    `);
});

// Customers page
app.get('/customers', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Customers - Management System</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
                .container { max-width: 1400px; margin: 0 auto; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                h1 { color: white; }
                button { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; transition: all 0.3s; }
                .btn-add { background: #4CAF50; color: white; margin-right: 10px; }
                .btn-back { background: #666; color: white; }
                .btn-edit { background: #2196F3; color: white; margin-right: 5px; }
                .btn-delete { background: #f44336; color: white; }
                button:hover { opacity: 0.8; transform: translateY(-2px); }
                table { width: 100%; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                th { background: #667eea; color: white; padding: 12px; text-align: left; }
                td { padding: 12px; border-bottom: 1px solid #ddd; }
                tr:hover { background: #f5f5f5; }
                .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; }
                .modal-content { background: white; padding: 30px; border-radius: 10px; width: 500px; max-width: 90%; }
                .modal-content h2 { margin-bottom: 20px; }
                input, select { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; }
                .form-group { margin-bottom: 15px; }
                .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>👥 Customer Management</h1>
                    <div>
                        <button class="btn-add" onclick="showAddModal()">+ Add Customer</button>
                        <button class="btn-back" onclick="window.location.href='/'">← Back to Home</button>
                    </div>
                </div>
                <table id="customersTable">
                    <thead>
                        <tr>
                            <th>Customer ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Phone</th>
                            <th>Membership</th>
                            <th>Total Spent</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="customersBody">
                        <tr><td colspan="7" style="text-align: center;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div id="modal" class="modal">
                <div class="modal-content">
                    <h2 id="modalTitle">Add Customer</h2>
                    <div class="form-group">
                        <label>Customer ID:</label>
                        <input type="text" id="customerId" placeholder="e.g., CUST004">
                    </div>
                    <div class="form-group">
                        <label>First Name:</label>
                        <input type="text" id="firstName" placeholder="First name">
                    </div>
                    <div class="form-group">
                        <label>Last Name:</label>
                        <input type="text" id="lastName" placeholder="Last name">
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" id="email" placeholder="Email">
                    </div>
                    <div class="form-group">
                        <label>Phone:</label>
                        <input type="text" id="phone" placeholder="Phone">
                    </div>
                    <div class="form-group">
                        <label>Membership:</label>
                        <select id="membership">
                            <option value="Silver">Silver</option>
                            <option value="Gold">Gold</option>
                            <option value="Platinum">Platinum</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Total Spent:</label>
                        <input type="number" id="totalSpent" placeholder="0.00" step="0.01">
                    </div>
                    <button class="btn-add" onclick="saveCustomer()">Save</button>
                    <button class="btn-back" onclick="closeModal()">Cancel</button>
                </div>
            </div>
            
            <script>
                let currentEditId = null;
                
                async function loadCustomers() {
                    try {
                        const response = await fetch('/api/customers');
                        const data = await response.json();
                        if(data.success && data.data.length > 0) {
                            document.getElementById('customersBody').innerHTML = data.data.map(customer => \`
                                <tr>
                                    <td>\${customer.customerId}</td>
                                    <td>\${customer.firstName} \${customer.lastName}</td>
                                    <td>\${customer.email}</td>
                                    <td>\${customer.phone || 'N/A'}</td>
                                    <td><span style="background: \${getMembershipColor(customer.membership)}; padding: 3px 10px; border-radius: 5px;">\${customer.membership}</span></td>
                                    <td>$\${customer.totalSpent.toFixed(2)}</td>
                                    <td>
                                        <button class="btn-edit" onclick="editCustomer('\${customer.customerId}')">Edit</button>
                                        <button class="btn-delete" onclick="deleteCustomer('\${customer.customerId}')">Delete</button>
                                    </td>
                                </tr>
                            \`).join('');
                        } else {
                            document.getElementById('customersBody').innerHTML = '<tr><td colspan="7" style="text-align: center;">No customers found</td></tr>';
                        }
                    } catch(error) {
                        console.error('Error:', error);
                        document.getElementById('customersBody').innerHTML = '<tr><td colspan="7" style="text-align: center;">Error loading customers</td></tr>';
                    }
                }
                
                function getMembershipColor(membership) {
                    switch(membership) {
                        case 'Platinum': return '#FFD700';
                        case 'Gold': return '#FFC107';
                        default: return '#C0C0C0';
                    }
                }
                
                function showAddModal() {
                    currentEditId = null;
                    document.getElementById('modalTitle').innerText = 'Add Customer';
                    document.getElementById('customerId').value = '';
                    document.getElementById('firstName').value = '';
                    document.getElementById('lastName').value = '';
                    document.getElementById('email').value = '';
                    document.getElementById('phone').value = '';
                    document.getElementById('membership').value = 'Silver';
                    document.getElementById('totalSpent').value = '0';
                    document.getElementById('modal').style.display = 'flex';
                }
                
                async function editCustomer(customerId) {
                    try {
                        const response = await fetch(\`/api/customers/\${customerId}\`);
                        const data = await response.json();
                        if(data.success && data.data) {
                            currentEditId = customerId;
                            document.getElementById('customerId').value = data.data.customerId;
                            document.getElementById('firstName').value = data.data.firstName;
                            document.getElementById('lastName').value = data.data.lastName;
                            document.getElementById('email').value = data.data.email;
                            document.getElementById('phone').value = data.data.phone || '';
                            document.getElementById('membership').value = data.data.membership;
                            document.getElementById('totalSpent').value = data.data.totalSpent;
                            document.getElementById('modalTitle').innerText = 'Edit Customer';
                            document.getElementById('modal').style.display = 'flex';
                        }
                    } catch(error) {
                        console.error('Error loading customer:', error);
                        alert('Error loading customer data');
                    }
                }
                
                async function saveCustomer() {
                    const customerData = {
                        customerId: document.getElementById('customerId').value,
                        firstName: document.getElementById('firstName').value,
                        lastName: document.getElementById('lastName').value,
                        email: document.getElementById('email').value,
                        phone: document.getElementById('phone').value,
                        membership: document.getElementById('membership').value,
                        totalSpent: parseFloat(document.getElementById('totalSpent').value),
                        createdAt: new Date().toISOString().split('T')[0]
                    };
                    
                    try {
                        let response;
                        if(currentEditId) {
                            response = await fetch(\`/api/customers/\${currentEditId}\`, {
                                method: 'PUT',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(customerData)
                            });
                        } else {
                            response = await fetch('/api/customers', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(customerData)
                            });
                        }
                        
                        const result = await response.json();
                        if(result.success) {
                            alert(currentEditId ? 'Customer updated successfully!' : 'Customer added successfully!');
                            closeModal();
                            loadCustomers();
                        } else {
                            alert('Error saving customer');
                        }
                    } catch(error) {
                        console.error('Error saving customer:', error);
                        alert('Error saving customer');
                    }
                }
                
                async function deleteCustomer(customerId) {
                    if(confirm('Are you sure you want to delete this customer?')) {
                        try {
                            const response = await fetch(\`/api/customers/\${customerId}\`, {
                                method: 'DELETE'
                            });
                            const result = await response.json();
                            if(result.success) {
                                alert('Customer deleted successfully!');
                                loadCustomers();
                            } else {
                                alert('Error deleting customer');
                            }
                        } catch(error) {
                            console.error('Error deleting customer:', error);
                            alert('Error deleting customer');
                        }
                    }
                }
                
                function closeModal() {
                    document.getElementById('modal').style.display = 'none';
                }
                
                loadCustomers();
            </script>
        </body>
        </html>
    `);
});

// Dashboard page
app.get('/dashboard', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Analytics</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                .btn-back { padding: 10px 20px; background: #666; color: white; text-decoration: none; border-radius: 5px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .stat-card { background: white; padding: 25px; border-radius: 10px; text-align: center; transition: transform 0.3s; }
                .stat-card:hover { transform: translateY(-5px); }
                .stat-value { font-size: 2.5em; font-weight: bold; color: #667eea; margin: 10px 0; }
                .recent-section { background: white; padding: 25px; border-radius: 10px; }
                .recent-section h3 { margin-bottom: 15px; color: #333; }
                .customer-item { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
                .customer-item:last-child { border-bottom: none; }
                .refresh-btn { background: #4CAF50; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; margin-left: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 System Dashboard</h1>
                    <div>
                        <button class="refresh-btn" onclick="loadAllData()">🔄 Refresh</button>
                        <a href="/" class="btn-back">← Back to Home</a>
                    </div>
                </div>
                
                <div class="stats-grid" id="stats"></div>
                
                <div class="recent-section">
                    <h3>📋 Recent Customers</h3>
                    <div id="recentCustomers">Loading...</div>
                </div>
            </div>
            
            <script>
                async function loadAllData() {
                    await loadStats();
                    await loadRecentCustomers();
                }
                
                async function loadStats() {
                    try {
                        const response = await fetch('/api/stats');
                        const data = await response.json();
                        if(data.success) {
                            document.getElementById('stats').innerHTML = \`
                                <div class="stat-card">
                                    <div class="stat-value">\${data.data.totalCustomers}</div>
                                    <div>Total Customers</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-value">\${data.data.totalAdmins}</div>
                                    <div>Total Admins</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-value">\${data.data.goldMembers}</div>
                                    <div>Gold Members</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-value">$\${data.data.totalRevenue.toFixed(2)}</div>
                                    <div>Total Revenue</div>
                                </div>
                            \`;
                        }
                    } catch(error) {
                        console.error('Error loading stats:', error);
                    }
                }
                
                async function loadRecentCustomers() {
                    try {
                        const response = await fetch('/api/customers');
                        const data = await response.json();
                        if(data.success && data.data.length > 0) {
                            const recent = data.data.slice(-5).reverse();
                            document.getElementById('recentCustomers').innerHTML = recent.map(customer => \`
                                <div class="customer-item">
                                    <div>
                                        <strong>\${customer.firstName} \${customer.lastName}</strong><br>
                                        <small>\${customer.email}</small>
                                    </div>
                                    <div>
                                        <span style="background: \${getMembershipColor(customer.membership)}; padding: 3px 10px; border-radius: 5px;">\${customer.membership}</span>
                                        <div style="margin-top: 5px;">$\${customer.totalSpent.toFixed(2)}</div>
                                    </div>
                                </div>
                            \`).join('');
                        } else {
                            document.getElementById('recentCustomers').innerHTML = '<p>No customers found</p>';
                        }
                    } catch(error) {
                        console.error('Error loading recent customers:', error);
                    }
                }
                
                function getMembershipColor(membership) {
                    switch(membership) {
                        case 'Platinum': return '#FFD700';
                        case 'Gold': return '#FFC107';
                        default: return '#C0C0C0';
                    }
                }
                
                loadAllData();
                setInterval(loadStats, 10000);
            </script>
        </body>
        </html>
    `);
});

// Admins page
app.get('/admins', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admins - Management System</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                .btn-back { padding: 10px 20px; background: #666; color: white; text-decoration: none; border-radius: 5px; }
                table { width: 100%; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                th { background: #667eea; color: white; padding: 12px; text-align: left; }
                td { padding: 12px; border-bottom: 1px solid #ddd; }
                tr:hover { background: #f5f5f5; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>👨‍💼 Admin Management</h1>
                    <button class="btn-back" onclick="window.location.href='/'">← Back to Home</button>
                </div>
                <table>
                    <thead>
                        <tr><th>Admin ID</th><th>Name</th><th>Email</th><th>Role</th><th>Created At</th></tr>
                    </thead>
                    <tbody id="adminsBody">
                        <tr><td colspan="5" style="text-align: center;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <script>
                async function loadAdmins() {
                    try {
                        const response = await fetch('/api/admins');
                        const data = await response.json();
                        if(data.success && data.data.length > 0) {
                            document.getElementById('adminsBody').innerHTML = data.data.map(admin => \`
                                <tr>
                                    <td>\${admin.adminId}</td>
                                    <td>\${admin.firstName} \${admin.lastName}</td>
                                    <td>\${admin.email}</td>
                                    <td>\${admin.role}</td>
                                    <td>\${admin.createdAt}</td>
                                </tr>
                            \`).join('');
                        } else {
                            document.getElementById('adminsBody').innerHTML = '<tr><td colspan="5" style="text-align: center;">No admins found</td></tr>';
                        }
                    } catch(error) {
                        console.error('Error loading admins:', error);
                    }
                }
                
                loadAdmins();
            </script>
        </body>
        </html>
    `);
});

// API Routes
app.get('/api/customers', async (req, res) => {
    try {
        const customers = await customersCollection.find().toArray();
        res.json({ success: true, data: customers });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/customers/:id', async (req, res) => {
    try {
        const customer = await customersCollection.findOne({ customerId: req.params.id });
        res.json({ success: true, data: customer });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/customers', async (req, res) => {
    try {
        const result = await customersCollection.insertOne(req.body);
        res.json({ success: true, message: 'Customer added!', id: result.insertedId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/customers/:customerId', async (req, res) => {
    try {
        const result = await customersCollection.updateOne(
            { customerId: req.params.customerId },
            { $set: req.body }
        );
        res.json({ success: true, message: 'Customer updated!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/customers/:customerId', async (req, res) => {
    try {
        const result = await customersCollection.deleteOne({ customerId: req.params.customerId });
        res.json({ success: true, message: 'Customer deleted!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/admins', async (req, res) => {
    try {
        const admins = await adminsCollection.find().toArray();
        res.json({ success: true, data: admins });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const totalCustomers = await customersCollection.countDocuments();
        const totalAdmins = await adminsCollection.countDocuments();
        const goldMembers = await customersCollection.countDocuments({ membership: "Gold" });
        const totalSpent = await customersCollection.aggregate([
            { $group: { _id: null, total: { $sum: "$totalSpent" } } }
        ]).toArray();
        
        res.json({
            success: true,
            data: {
                totalCustomers,
                totalAdmins,
                goldMembers,
                totalRevenue: totalSpent[0]?.total || 0
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start server
connectDB().then(() => {
    app.listen(PORT, () => {
        console.log('\n═══════════════════════════════════════════════════════');
        console.log('🚀 Server is running successfully!');
        console.log('═══════════════════════════════════════════════════════');
        console.log(`📍 URL: http://localhost:${PORT}`);
        console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
        console.log(`👥 Customers: http://localhost:${PORT}/customers`);
        console.log(`👨‍💼 Admins: http://localhost:${PORT}/admins`);
        console.log('═══════════════════════════════════════════════════════\n');
    });
});
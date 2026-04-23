const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
    adminId: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    role: {
        type: String,
        enum: ['Super Admin', 'Admin', 'Moderator', 'Viewer'],
        default: 'Admin'
    },
    phone: {
        type: String,
        default: ''
    },
    department: {
        type: String,
        default: ''
    },
    managedCustomers: {
        type: Number,
        default: 0
    },
    joinDate: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    lastActive: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive'],
        default: 'Active'
    }
});

module.exports = mongoose.model('Admin', adminSchema);
const mongoose = require('mongoose');

const customerSchema = new mongoose.Schema({
    customerId: {
        type: String,
        required: true,
        unique: true
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    phone: {
        type: String,
        default: ''
    },
    membership: {
        type: String,
        enum: ['Silver', 'Gold', 'Platinum'],
        default: 'Silver'
    },
    totalSpent: {
        type: Number,
        default: 0
    },
    orders: {
        type: Number,
        default: 0
    },
    rating: {
        type: Number,
        default: 4.0
    },
    lastActive: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    joinDate: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    address: {
        street: String,
        city: String,
        zipCode: String
    }
});

module.exports = mongoose.model('Customer', customerSchema);
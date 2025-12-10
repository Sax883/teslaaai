// data.js
const clients = [
    { clientID: 'C001', name: 'Alice Smith', totalBalance: 15500.50, totalProfit: 450.75, activeInvestment: 12000.00, nextPayout: '2025-12-15' },
    { clientID: 'C002', name: 'Bob Johnson', totalBalance: 8200.00, totalProfit: 120.10, activeInvestment: 7500.00, nextPayout: '2025-12-20' },
    { clientID: 'C003', name: 'Charlie Brown', totalBalance: 25000.75, totalProfit: 950.90, activeInvestment: 20000.00, nextPayout: '2025-12-10' },
];

const adminUser = { 
    id: 1, 
    username: 'admin', 
    password: 'password123', // <-- This field is essential for server.js login
    name: 'System Admin', 
    role: 'admin' 
};

module.exports = { clients, adminUser };
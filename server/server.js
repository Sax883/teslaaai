// server.js - Final Update for PostgreSQL (using async/await with db.query)
const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cors = require('cors'); 

// --- CRITICAL PATH ADJUSTMENT ---
// FIX: The server.js is in /server, but index.html is in the root. 
// We must point to the parent directory (..).
const ROOT_DIR = path.join(__dirname, '..'); // <-- THIS IS THE CRITICAL FIX

// --- CRITICAL CHANGE: Import the new PostgreSQL-compatible database module ---
const db = require('./database'); // This now exports { query, pool }

// --- 1. Load Data and Setup ---
const adminUser = {
    id: 'ADMIN000',
    name: 'Main Admin',
    username: 'telsa_ai', 
    password: '@Divine081', // WARNING: This should be hashed in production!
    role: 'admin'
};
// IMPORTANT: Load from env for production!
const SECRET_KEY = process.env.JWT_SECRET || 'YOUR_SUPER_SECRET_KEY_FALLBACK'; 

// Chat History structure (In-memory storage)
const chatHistory = {};

// Track which clients are online and in the support system
const onlineClientSockets = new Map(); // Key: clientID, Value: socket.id
const ADMIN_ROOM = 'admin-room'; // Room for Admin notifications

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Allow all origins for simplicity in testing
        methods: ["GET", "POST", "PUT"]
    }
});

// Middlewares
app.use(bodyParser.json());
app.use(cors({
    origin: "*", // Allow all origins for API routes
    methods: ["GET", "POST", "PUT", "DELETE"]
})); 


// --- 3. API Routes (Client and Admin) ---
// 🚨 CRITICAL FIX: Define and link apiRouter immediately after global middleware 
const apiRouter = express.Router();
app.use('/api', apiRouter);


// Static file serving
// This must be placed AFTER the API router link (app.use('/api', apiRouter))
// Since ROOT_DIR is the parent (repo root), this now correctly serves index.html.
app.use(express.static(ROOT_DIR)); 


// --- Helper Functions for Socket.IO Broadcasts ---

/**
 * Helper function to broadcast the current list of online clients to the admin room.
 */
function broadcastOnlineClients() {
    const clients = Array.from(onlineClientSockets.keys());
    io.to(ADMIN_ROOM).emit('online-clients', clients);
}

/**
 * Helper function to fetch the client's recent activity and broadcast it.
 * @param {string} clientID The ID of the client to fetch activity for.
 */
async function broadcastRecentActivity(clientID) {
    const sql = `
        SELECT 
            type, 
            amount, 
            timestamp,
            "transactionID",
            status 
        FROM transactions
        WHERE "clientID" = $1
        ORDER BY timestamp DESC
        LIMIT 10
    `;
    
    try {
        const result = await db.query(sql, [clientID]);
        const activity = result.rows;
        
        // Emit the latest activity list to the specific client's room
        io.to(clientID).emit('activity-update', activity); 
        console.log(`[SOCKET.IO] Broadcasted ${activity.length} recent activities for Client: ${clientID}`);
    } catch (err) {
        console.error(`Error fetching activity for broadcast for Client ${clientID}:`, err.message);
    }
}


// --- 2. Authentication Middlewares ---

/**
 * Middleware for Admin authentication.
 */
function verifyAdminToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Access Denied: No Admin Token Provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== 'admin') {
            return res.status(403).send({ message: 'Forbidden: Insufficient Permissions (Not Admin)' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).send({ message: 'Invalid Admin Token' });
    }
}

/**
 * Middleware for Client authentication.
 */
function verifyClientToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Access Denied: No Client Token Provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role !== 'client') {
            return res.status(403).send({ message: 'Forbidden: Insufficient Permissions (Not Client)' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).send({ message: 'Invalid Client Token' });
    }
}


// 🌟 ADMIN API ROUTES 🌟

apiRouter.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    if (username === adminUser.username && password === adminUser.password) {
        const token = jwt.sign(
            { id: adminUser.id, name: adminUser.name, role: 'admin' },
            SECRET_KEY,
            { expiresIn: '1h' }
        );
        return res.json({ token, name: adminUser.name });
    }

    res.status(401).json({ message: 'Invalid Admin credentials' });
});

// ✅ UPDATED ADMIN ROUTE: Update Transaction Status (The Secure Verification Step)
apiRouter.put('/admin/transaction/:id', verifyAdminToken, async (req, res) => {
    const { id } = req.params;
    const { status, clientID } = req.body; 
    
    if (!['Completed', 'Declined'].includes(status) || !clientID) {
        return res.status(400).json({ message: 'Invalid status or missing clientID.' });
    }
    
    try {
        // 1. Update the transaction status in the DB
        const updateSql = `
            UPDATE transactions
            SET status = $1
            WHERE "transactionID" = $2
        `;
        const result = await db.query(updateSql, [status, id]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ message: `Transaction ID ${id} not found.` });
        }

        // 2. Successful update response
        res.json({ message: `Transaction ${id} marked as ${status}.` });

        // 3. Notify Client Dashboard of Final Status
        broadcastRecentActivity(clientID); 
        
    } catch (err) {
        console.error("Database error updating transaction status:", err.message);
        return res.status(500).json({ message: 'Failed to update transaction status.' });
    }
});


apiRouter.get('/admin/profile', verifyAdminToken, (req, res) => {
    res.json({ id: req.user.id, name: req.user.name, role: req.user.role });
});

// ✅ UPDATED ADMIN ROUTE: Get All Clients
apiRouter.get('/admin/clients', verifyAdminToken, async (req, res) => {
    const sql = `
        SELECT 
            "clientID", 
            email, 
            "totalBalance" AS balance, 
            "activeInvestment" AS investment, 
            "totalProfit" AS profit,
            "nextPayout"
        FROM clients
    `;
    try {
        const result = await db.query(sql);
        res.json(result.rows);
    } catch (err) {
        console.error("Database error fetching clients:", err.message);
        return res.status(500).json({ message: 'Database error fetching clients.' }); 
    }
});

// ✅ UPDATED ADMIN ROUTE: Client Update Route (used by Admin to adjust financials)
apiRouter.put('/admin/client/:clientID', verifyAdminToken, async (req, res) => {
    const { clientID } = req.params;
    const { balance, investment, profit, nextPayout } = req.body; 

    const sql = `
        UPDATE clients
        SET "totalBalance" = $1, "activeInvestment" = $2, "totalProfit" = $3, "nextPayout" = $4
        WHERE "clientID" = $5
    `;
    const params = [
        parseFloat(balance), 
        parseFloat(investment), 
        parseFloat(profit), 
        nextPayout, 
        clientID
    ];

    try {
        const updateResult = await db.query(sql, params);

        if (updateResult.rowCount === 0) {
            return res.status(404).json({ message: `Client ID ${clientID} not found or no changes were applied.` }); 
        }
        
        // 1. Fetch the newly updated data from the DB to get the latest values
        const selectSql = `
            SELECT 
                "clientID", "totalBalance" AS balance, "activeInvestment" AS investment, "totalProfit" AS profit, "nextPayout"
            FROM clients
            WHERE "clientID" = $1
        `;

        const selectResult = await db.query(selectSql, [clientID]);
        const updatedData = selectResult.rows[0];

        // 2a. Broadcast 'financial-update' for the financial metrics
        if (updatedData) {
            console.log(`Broadcasting financial-update for Client: ${clientID}`);
            io.to(clientID).emit('financial-update', updatedData);
        } else {
             console.error(`Client data not found after update for clientID: ${clientID}`);
        }
        
        // 2b. Broadcast 'activity-update' to refresh the activity table
        broadcastRecentActivity(clientID); 

        // 3. Send the API response back to the Admin
        res.json({ message: `Client ID ${clientID} updated successfully.`, changes: updateResult.rowCount });
        
    } catch (err) {
        console.error("Database error updating client:", err.message);
        return res.status(500).json({ message: 'Database error updating client.' });
    }
});

// 🌟 CLIENT API ROUTES 🌟

// ✅ UPDATED CLIENT ROUTE: Log Transaction Claim (Deposit, Withdraw, Car, Plan)
apiRouter.post('/client/transaction', verifyClientToken, async (req, res) => {
    const clientID = req.user.id;
    const { type, amount } = req.body; 
    
    if (!type || !amount || isNaN(amount) || parseFloat(amount) <= 0) {
        return res.status(400).json({ message: 'Invalid transaction type or amount.' });
    }

    try {
        // 1. Log the transaction claim with PENDING status
        const insertSql = `
            INSERT INTO transactions ("clientID", type, amount, status, timestamp)
            VALUES ($1, $2, $3, 'Pending', NOW())
            RETURNING "transactionID"
        `;
        const insertParams = [clientID, type, parseFloat(amount)];

        const insertResult = await db.query(insertSql, insertParams);
        const newTransactionID = insertResult.rows[0].transactionID;
        
        // 2. Success Response: Send the "Confirmation" message
        res.json({ 
            message: `Your ${type} claim has been recorded and is awaiting Admin confirmation.`, 
            status: 'Pending',
            transactionID: newTransactionID
        });

        // 3. Broadcast Real-Time Update to the client's dashboard
        broadcastRecentActivity(clientID); 
        
        // 4. Admin Notification: Alert the admin dashboard that a new claim needs verification.
        io.to(ADMIN_ROOM).emit('new-pending-claim', { 
            clientID, 
            type, 
            amount,
            transactionID: newTransactionID
        });
        
    } catch (err) {
        console.error("Database error logging pending transaction:", err.message);
        return res.status(500).json({ message: 'Failed to record transaction claim.' });
    }
});


// ⭐ FIXED CLIENT ROUTE: Register (Hyper-Defensive ID Generation)
apiRouter.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required.' });
    }

    try {
        // 1. Check if email exists
        const checkSql = 'SELECT "clientID" FROM clients WHERE email = $1';
        const checkResult = await db.query(checkSql, [email]);
        
        if (checkResult.rows.length > 0) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        // 2. Determine the next clientID: Count all non-admin clients and increment
        const countSql = `
            SELECT COUNT(*) AS total_clients
            FROM clients
            WHERE "clientID" NOT LIKE 'ADMIN%'
        `;
        
        const countResult = await db.query(countSql);
        
        let clientCount = 0;
        
        // --- DEFENSIVE CHECK ---
        if (countResult.rows && countResult.rows.length > 0) {
            // Ensure the value is treated as an integer, defaulting to 0 if null/invalid.
            clientCount = parseInt(countResult.rows[0].total_clients || 0); 
        }
        // --- END DEFENSIVE CHECK ---

        // Generate new ID (e.g., 0001, 0002, 0003, etc.)
        const nextIDNumber = clientCount + 1;
        const newClientID = nextIDNumber.toString().padStart(4, '0'); 
        
        console.log(`Attempting to register new client with ID: ${newClientID}`);

        // 3. Insert new client (Includes the $200 welcome bonus from database.js default)
        const insertSql = `
            INSERT INTO clients ("clientID", name, email, password, "totalBalance", "totalProfit", "activeInvestment", "nextPayout")
            VALUES ($1, $2, $3, $4, 200.00, 0.00, 0.00, NULL) 
        `;
        
        const params = [newClientID, name, email, password];
        await db.query(insertSql, params);
        
        console.log(`Successfully registered client ${newClientID}. Generating token...`);

        // 4. Generate JWT Token
        const token = jwt.sign(
            { id: newClientID, name, role: 'client' },
            SECRET_KEY,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'Registration successful. Auto-logging in.',
            token,
            client: { clientID: newClientID, name }
        });

    } catch (err) {
        // Log the full error object for better debugging
        console.error("Database error during registration:", err); 
        // Note: For a true failure (DB connection down), you might want to exit or log more severely.
        return res.status(500).json({ message: 'Database error during registration.' });
    }
});

// ✅ UPDATED CLIENT ROUTE: Login
apiRouter.post('/client-login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const sql = 'SELECT "clientID", name, password FROM clients WHERE email = $1';
        const result = await db.query(sql, [email]);
        const client = result.rows[0];

        if (client && client.password === password) {
            const token = jwt.sign(
                { id: client.clientID, name: client.name, role: 'client' },
                SECRET_KEY,
                { expiresIn: '24h' } 
            );
            return res.json({ token, name: client.name, clientID: client.clientID });
        }

        res.status(401).json({ message: 'Invalid email or password.' });
    } catch (err) {
        console.error("Database error during client login:", err.message);
        return res.status(500).json({ message: 'Database error during login.' });
    }
});


// ✅ UPDATED CLIENT ROUTE: Get Client Profile
apiRouter.get('/client/me', verifyClientToken, async (req, res) => {
    const clientID = req.user.id;

    // CRITICAL FIX IMPLEMENTED HERE: Cast "nextPayout" to TEXT to prevent front-end rendering errors if null.
    const sql = `
        SELECT 
            "clientID", 
            name, 
            email, 
            "totalBalance" AS balance, 
            "totalProfit" AS profit, 
            "activeInvestment" AS investment, 
            CAST("nextPayout" AS TEXT) AS "nextPayout" 
        FROM clients 
        WHERE "clientID" = $1
    `;
    try {
        const result = await db.query(sql, [clientID]);
        const clientData = result.rows[0];
        
        if (!clientData) {
            return res.status(404).json({ message: 'Client data not found' });
        }

        res.json(clientData);
    } catch (err) {
        console.error("Database error fetching client data:", err.message);
        return res.status(500).json({ message: 'Database error fetching client data.' });
    }
});


// --- 4. HTML Serving Routes (SPA Routing) ---

/**
 * Handle root '/' and /admin.html explicitly to ensure they are served correctly.
 */
// Explicitly define the route for the Admin page
app.get('/admin.html', (req, res) => {
    const adminHtmlPath = path.join(ROOT_DIR, 'admin.html');
    if (fs.existsSync(adminHtmlPath)) {
        return res.sendFile(adminHtmlPath);
    }
    // If admin.html doesn't exist, fall through to the SPA route
    res.status(404).send('Admin file not found.');
});

// Explicitly define the route for the client root
app.get('/', (req, res) => {
    const indexHtmlPath = path.join(ROOT_DIR, 'index.html');
    if (fs.existsSync(indexHtmlPath)) {
        return res.sendFile(indexHtmlPath);
    }
    res.status(500).send('Client entry point (index.html) not found.');
});


// Catch-all route for SPA client-side routing (e.g., /dashboard, /login)
app.use((req, res, next) => {
    // Only process GET requests that don't start with /api 
    // and that haven't been handled by express.static or the routes above.
    if (req.method === 'GET' && !req.path.startsWith('/api')) {
        
        // Serve index.html for all other client paths (SPA routing)
        const indexHtmlPath = path.join(ROOT_DIR, 'index.html');
        if (fs.existsSync(indexHtmlPath)) {
            // This is the SPA catch-all
            return res.sendFile(indexHtmlPath);
        }

        // Fallback 404
        return res.status(404).send('404 Not Found');
    }
    
    // If it's a non-GET request or starts with /api, and hasn't been handled, 
    // it likely means the API route was not found (404), or the method is wrong (405).
    // Express will typically handle 404/405 automatically after this point if no route matches.
    next();
});


// --- 5. Socket.IO (Live Chat and Financial Updates) ---
io.on('connection', (socket) => {
    console.log(`Socket connected: ${socket.id}`);
    
    socket.data.clientID = null;

    // --- Admin Event Handlers ---

    socket.on('join-admin-room', () => {
        console.log(`Admin socket ${socket.id} joined admin room.`);
        socket.join(ADMIN_ROOM);
        broadcastOnlineClients();
    });

    socket.on('get-chat-history', (clientID) => {
        console.log(`Admin requested history for ${clientID}`);
        socket.emit('chat-history', chatHistory[clientID] || []);
    });

    socket.on('admin-reply', (data) => {
        const { recipientID, message } = data; 
        
        const chatMsg = {
            sender: 'admin',
            text: message,
            timestamp: Date.now()
        };

        if (!chatHistory[recipientID]) chatHistory[recipientID] = [];
        chatHistory[recipientID].push(chatMsg);

        io.to(recipientID).emit('new-admin-reply', chatMsg);
    });

    // --- Client Event Handlers ---

    socket.on('client-join-support', (clientID) => {
        console.log(`Client ${clientID} joined support.`);
        
        // IMPORTANT: Client socket joins a room named after its ID. 
        // This is used by the Admin route above to send targeted financial and activity updates.
        socket.join(clientID); 
        onlineClientSockets.set(clientID, socket.id);
        socket.data.clientID = clientID;
        
        broadcastOnlineClients();
        
        socket.emit('chat-history', chatHistory[clientID] || []);
    });

    socket.on('client-send-message', (data) => {
        const { clientID, message } = data;

        const chatMsg = {
            sender: 'client',
            text: message,
            timestamp: Date.now(),
            senderID: clientID 
        };
        
        if (!chatHistory[clientID]) chatHistory[clientID] = [];
        chatHistory[clientID].push(chatMsg);

        io.to(ADMIN_ROOM).emit('client-message', chatMsg);
    });


    // --- Disconnect Handler ---

    socket.on('disconnect', () => {
        const disconnectedClientID = socket.data.clientID;
        
        if (disconnectedClientID) {
            onlineClientSockets.delete(disconnectedClientID);
            console.log(`Client ${disconnectedClientID} disconnected.`);
            broadcastOnlineClients();
        } else if (socket.rooms.has(ADMIN_ROOM)) {
            console.log(`Admin disconnected: ${socket.id}`);
        } else {
             console.log(`Generic user disconnected: ${socket.id}`);
        }
    });
});


// --- 6. Start Server ---
// Use the environment variable PORT provided by Render, default to 3000 for local development.
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    // NOTE: For live environment, these localhost URLs are for local testing reference only.
    console.log(`Access the application at: http://localhost:${PORT}/`);
    console.log(`Admin Panel: http://localhost:${PORT}/admin.html`);
});
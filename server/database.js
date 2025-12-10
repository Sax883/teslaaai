// database.js - Updated for PostgreSQL (Required for Render's permanent storage)
const { Pool } = require('pg');

// Render automatically provides the DATABASE_URL environment variable 
// (which you must set in your Web Service environment settings).
const connectionString = process.env.DATABASE_URL; 

if (!connectionString) {
    console.error("FATAL ERROR: DATABASE_URL environment variable is not set. Cannot connect to PostgreSQL.");
    // In a production environment, this should cause the application to fail hard and fast.
    process.exit(1); 
}

// Create a connection pool to manage database connections efficiently
const pool = new Pool({
    connectionString: connectionString,
    // This configuration is necessary for connecting to the cloud database securely.
    ssl: {
        rejectUnauthorized: false
    }
});

/**
 * Executes a query using a client from the pool.
 * @param {string} text The SQL query text.
 * @param {Array<any>} params The parameters for the query.
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(text, params) {
    const client = await pool.connect();
    try {
        const res = await client.query(text, params);
        return res;
    } catch (err) {
        console.error('PostgreSQL Query Error:', err.message, 'SQL:', text, 'Params:', params);
        throw err;
    } finally {
        client.release();
    }
}

// --- Initialize Tables ---
async function initializeDatabase() {
    let client;
    try {
        client = await pool.connect();
        console.log('Successfully connected to PostgreSQL.');
        client.release();

        console.log('Attempting to initialize tables...');
        
        // ... (Table creation logic remains the same) ...

        await query(`
            CREATE TABLE IF NOT EXISTS clients (
                "clientID" TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                "totalBalance" REAL DEFAULT 200.00, 
                "totalProfit" REAL DEFAULT 0.00,
                "activeInvestment" REAL DEFAULT 0.00,
                "nextPayout" TEXT DEFAULT NULL
            )
        `);
        
        await query(`
            CREATE TABLE IF NOT EXISTS transactions (
                "transactionID" SERIAL PRIMARY KEY,
                "clientID" TEXT NOT NULL,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY ("clientID") REFERENCES clients("clientID")
            )
        `);
        console.log('PostgreSQL tables initialized successfully.');

        // 3. Admin User Check 
        const adminEmail = 'admin@teslaai.com';
        const adminCheck = await query('SELECT "clientID" FROM clients WHERE email = $1', [adminEmail]);
        
        if (adminCheck.rows.length === 0) {
            await query(`
                INSERT INTO clients ("clientID", name, email, password, "totalBalance", "activeInvestment", "totalProfit", "nextPayout")
                VALUES ($1, $2, $3, $4, 0.00, 0.00, 0.00, NULL)
            `, ['ADMIN000', 'Main Admin', adminEmail, '@Divine081']);
            console.log('Default Admin user created with ID ADMIN000.');
        }

    } catch (err) {
        console.error('FATAL ERROR: Error during PostgreSQL connection or initialization:');
        console.error(err); 
        process.exit(1);
    }
}

// Start the initialization process
initializeDatabase();

// Export the query function for use in server.js routes
module.exports = { query, pool };
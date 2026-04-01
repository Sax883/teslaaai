// database.js - Supports PostgreSQL on Render and SQLite fallback for local/testing use
const path = require('path');
const { Pool } = require('pg');
const sqlite3 = require('sqlite3').verbose();

const connectionString = process.env.DATABASE_URL;
let pool;
let query;
let sqliteDb;

function normalizeSqlForSqlite(sql) {
    return sql
        .replace(/\$(\d+)/g, '?')
        .replace(/SERIAL PRIMARY KEY/gi, 'INTEGER PRIMARY KEY AUTOINCREMENT')
        .replace(/TIMESTAMPTZ/gi, 'TEXT')
        .replace(/NOW\(\)/gi, 'CURRENT_TIMESTAMP');
}

if (connectionString) {
    console.log('Using PostgreSQL database connection.');

    pool = new Pool({
        connectionString,
        ssl: {
            rejectUnauthorized: false
        }
    });

    query = async function queryPostgres(text, params = []) {
        const client = await pool.connect();
        try {
            return await client.query(text, params);
        } catch (err) {
            console.error('PostgreSQL Query Error:', err.message, 'SQL:', text, 'Params:', params);
            throw err;
        } finally {
            client.release();
        }
    };
} else {
    const sqlitePath = path.join(__dirname, 'teslaai.db');
    console.warn(`DATABASE_URL not set. Falling back to SQLite at ${sqlitePath}.`);

    sqliteDb = new sqlite3.Database(sqlitePath);
    sqliteDb.serialize(() => {
        sqliteDb.run('PRAGMA foreign_keys = ON');
    });

    const executeSqlite = (text, params = []) => new Promise((resolve, reject) => {
        const sql = normalizeSqlForSqlite(text.trim());

        if (/^SELECT/i.test(sql)) {
            sqliteDb.all(sql, params, (err, rows) => {
                if (err) {
                    console.error('SQLite Query Error:', err.message, 'SQL:', sql, 'Params:', params);
                    reject(err);
                    return;
                }
                resolve({ rows, rowCount: rows.length });
            });
            return;
        }

        sqliteDb.run(sql, params, function onRun(err) {
            if (err) {
                console.error('SQLite Query Error:', err.message, 'SQL:', sql, 'Params:', params);
                reject(err);
                return;
            }
            resolve({ rows: [], rowCount: this.changes ?? 0, lastID: this.lastID });
        });
    });

    query = executeSqlite;
    pool = {
        connect: async () => ({
            query: executeSqlite,
            release() {}
        })
    };
}

async function initializeDatabase() {
    try {
        if (connectionString) {
            const client = await pool.connect();
            console.log('Successfully connected to PostgreSQL.');
            client.release();
        } else {
            console.log('Successfully connected to SQLite.');
        }

        console.log('Attempting to initialize tables...');

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
                "transactionID" ${connectionString ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
                "clientID" TEXT NOT NULL,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                timestamp ${connectionString ? 'TIMESTAMPTZ NOT NULL DEFAULT NOW()' : 'TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP'},
                FOREIGN KEY ("clientID") REFERENCES clients("clientID")
            )
        `);
        console.log(`${connectionString ? 'PostgreSQL' : 'SQLite'} tables initialized successfully.`);

        const adminClientID = 'ADMIN000';
        const adminEmail = 'support@telsaai.co';
        const adminCheck = await query('SELECT "clientID" FROM clients WHERE "clientID" = $1', [adminClientID]);

        if (adminCheck.rows.length === 0) {
            const bcrypt = require('bcrypt');
            const adminRawPassword = process.env.ADMIN_PASSWORD || '@Divine081';
            const adminHashedPassword = await bcrypt.hash(adminRawPassword, 10);
            await query(`
                INSERT INTO clients ("clientID", name, email, password, "totalBalance", "activeInvestment", "totalProfit", "nextPayout")
                VALUES ($1, $2, $3, $4, 0.00, 0.00, 0.00, NULL)
            `, [adminClientID, 'Main Admin', adminEmail, adminHashedPassword]);
            console.log('Default Admin user created with ID ADMIN000.');
        } else {
            console.log('Admin user with ID ADMIN000 already exists. Skipping seed insert.');
        }
    } catch (err) {
        console.error('FATAL ERROR: Error during database connection or initialization:');
        console.error(err);
        process.exit(1);
    }
}

initializeDatabase();

module.exports = { query, pool };
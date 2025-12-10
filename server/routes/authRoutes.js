const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();
const JWT_SECRET = 'YOUR_SUPER_SECRET_KEY'; // ⚠️ **CHANGE THIS TO A LONG, RANDOM STRING**

// --- 1. SIGNUP Route ---
router.post('/signup', async (req, res) => {
    const { email, password, name } = req.body;
    try {
        const user = new User({ email, password, name });
        await user.save();
        res.status(201).json({ message: 'User registered successfully. You can now log in.' });
    } catch (error) {
        if (error.code === 11000) { // MongoDB duplicate key error (email already exists)
            return res.status(409).json({ message: 'Email already registered.' });
        }
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

// --- 2. LOGIN Route (Device-Agnostic Authentication) ---
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // Authentication SUCCESS! Create a JWT token.
        // This token contains the user ID and is what the client uses for every other request.
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' } // Token expires in 7 days
        );

        // Send the token back to the client
        res.json({ 
            message: 'Login successful',
            token: token, // This is the 'userToken' your dashboard JS will store
            // Add basic user info for immediate display
            user: {
                name: user.name,
                clientID: user.clientID,
                email: user.email
            }
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});

module.exports = router;
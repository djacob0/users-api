const jwt = require("jsonwebtoken");
const UserModel = require("../models/UserModel");
require("dotenv").config();

const SECRET_KEY = process.env.JWT_SECRET || "my_very_secret_key";

async function authenticate(req, res, next) {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Access denied, no token provided" });

        // Verify token
        const decoded = jwt.verify(token, SECRET_KEY);

        // Check if session is active in the database
        const session = await UserModel.getSession(token);
        if (!session) return res.status(401).json({ message: "Session expired or invalid" });

        req.user = decoded; // Attach user data to request
        next();
    } catch (err) {
        res.status(401).json({ message: "Invalid or expired token" });
    }
}

module.exports = authenticate;

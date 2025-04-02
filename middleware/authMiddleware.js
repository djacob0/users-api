// const jwt = require("jsonwebtoken");
// const UserModel = require("../models/UserModel");
// require("dotenv").config();

// const SECRET_KEY = process.env.SECRET_KEY || "my_very_secret_key";

// async function authenticate(req, res, next) {
//     try {
//         console.log("Incoming Request Headers:", req.headers);

//         const token = req.headers.authorization?.split(" ")[1]; // Extract token
//         if (!token) {
//             console.log("❌ No Token Found");
//             return res.status(401).json({ message: "Access denied, no token provided" });
//         }

//         const decoded = jwt.verify(token, SECRET_KEY);
//         console.log("✅ Decoded Token:", decoded);

//         // Validate session in DB
//         const session = await UserModel.getSession(token);
//         console.log("🔍 Session Found:", session);

//         if (!session) {
//             console.log("❌ Session Expired or Invalid");
//             return res.status(401).json({ message: "Session expired or invalid" });
//         }

//         req.user = decoded; // Attach user data to request
//         console.log("✔ User Attached to Request:", req.user);

//         next();
//     } catch (err) {
//         console.error("❌ Authentication Error:", err.message);
//         res.status(401).json({ message: "Invalid or expired token" });
//     }
// }

// module.exports = authenticate;

const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken");
const UserModel = require("../models/UserModel");
require("dotenv").config();

const SECRET_KEY = process.env.JWT_SECRET || "my_very_secret_key"; 
class UserController {
  static async getAllUsers(req, res) {
    try {
      const users = await UserModel.getAllUsers();
      res.json(users);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  static async getUserById(req, res) {
    try {
      const user = await UserModel.getUserById(req.params.id);
      if (!user) return res.status(404).json({ message: "User not found" });
      res.json(user);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  static async registerUser(req, res) {
    try {
        console.log("Request User:", req.user);

        const allowedFields = ["username", "password", "email", "firstName", "middleName", "lastName"];
        const userData = {};

        Object.keys(req.body).forEach((key) => {
            if (allowedFields.includes(key)) {
                userData[key] = req.body[key];
            }
        });

        if (!userData.username || !userData.password || !userData.email) {
            return res.status(400).json({ message: "Username, password, and email are required" });
        }

        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: "Unauthorized: Invalid session" });
        }

        userData.created_by = req.user.id; // ✅ Set created_by from logged-in user

        const existingUser = await UserModel.getUserByUsername(userData.username);
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists" });
        }

        const userId = await UserModel.createUser(userData);
        res.status(201).json({ message: "User registered successfully", userId });
    } catch (err) {
        console.error("Register Error:", err.message);
        res.status(500).json({ error: err.message });
    }
}


    static async loginUser(req, res) {
      try {
          const { username, password } = req.body;
          if (!username || !password) {
              return res.status(400).json({ message: "Username and password are required" });
          }

          const user = await UserModel.getUserByUsername(username);
          if (!user) return res.status(404).json({ message: "User not found" });

          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

          // Generate JWT token
          const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: "1h" });

          // Get user IP and User-Agent
          const ipAddress = req.ip;
          const userAgent = req.headers["user-agent"];

          // Store session in database
          await UserModel.createSession(user.id, token, ipAddress, userAgent);

          res.json({ message: "Login successful", token, user: { id: user.id, username: user.username } });
      } catch (err) {
          res.status(500).json({ error: err.message });
      }
  }

  static async logoutUser(req, res) {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "No token provided" });
        }

        const token = authHeader.split(" ")[1];

        // Verify token before expiring session
        try {
            const decoded = jwt.verify(token, SECRET_KEY);
            const session = await UserModel.getSession(token);
            if (!session) {
                return res.status(400).json({ message: "Session not found or already logged out" });
            }
        } catch (error) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }

        // Expire session in database
        const success = await UserModel.expireSession(token);
        if (!success) return res.status(400).json({ message: "Invalid session or already logged out" });

        res.json({ message: "Logout successful" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
} 
  static async updateUser(req, res) {
    try {
      const userId = req.params.id;
      const updatedBy = req.body.updated_by || req.user?.id;

      const updated = await UserModel.updateUser(userId, req.body, updatedBy);
      if (!updated) return res.status(404).json({ message: "User not found" });

      res.json({ message: "User updated successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }

  static async deleteUser(req, res) {
    try {
      const deleted = await UserModel.deleteUser(req.params.id);
      if (!deleted) return res.status(404).json({ message: "User not found" });
      res.json({ message: "User deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
}

module.exports = UserController;

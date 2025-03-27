const bcrypt = require("bcryptjs"); // Hash passwords
const jwt = require("jsonwebtoken");
const UserModel = require("../models/UserModel");
require("dotenv").config();

const SECRET_KEY = process.env.JWT_SECRET || "my_very_secret_key"; // Use env variable for security

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
          const { username, password, email, created_by } = req.body;

          if (!username || !password || !email) {
              return res.status(400).json({ message: "All fields are required" });
          }

          const existingUser = await UserModel.getUserByUsername(username);
          if (existingUser) {
              return res.status(400).json({ message: "Username already exists" });
          }

          const userId = await UserModel.createUser({ username, password, email, created_by });
          res.status(201).json({ message: "User registered successfully", userId });
      } catch (err) {
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
          const token = req.headers.authorization?.split(" ")[1];
          if (!token) return res.status(401).json({ message: "No token provided" });

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

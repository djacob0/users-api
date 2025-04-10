const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const UserModel = require("../models/UserModel");
const OtpModel = require("../models/OtpModel");
const nodemailer = require("nodemailer");
require("dotenv").config();
const db = require("../config/db");

const getAllUsers = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });
        jwt.verify(token, process.env.JWT_SECRET);
        const users = await UserModel.getAllUsers();

        res.json({ users });
    } catch (error) {
        console.error("Get All Users Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const createUser = async (req, res) => {
    try {
        const { username, password, email, firstName, lastName, middleName, phoneNumber } = req.body;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const loggedInUserId = decoded.userId;

        if (!username || !password || !email || !firstName || !lastName) {
            return res.status(400).json({ message: "All required fields must be filled" });
        }

        const existingUser = await UserModel.getUserByEmail(email);
        if (existingUser) return res.status(400).json({ message: "Username already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        await UserModel.createUser({
            username,
            password: hashedPassword,
            email,
            firstName,
            middleName,
            lastName,
            phoneNumber
        }, loggedInUserId);

        res.status(201).json({ message: "User created successfully" });
    } catch (error) {
        console.error("Create User Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const updateUser = async (req, res) => {
    try {
        const userIdToUpdate = req.params.id;
        const { created_at, deleted_at, ...updateFields } = req.body;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const loggedInUserId = decoded.userId;

        if (!userIdToUpdate) return res.status(400).json({ message: "User ID is required" });

        const user = await UserModel.getUserById(userIdToUpdate);
        if (!user) return res.status(404).json({ message: "User not found" });

        const updateData = {
            ...updateFields,
            id: userIdToUpdate,
            updated_by: loggedInUserId,
            updated_at: new Date(),
        };

        await UserModel.updateUser(loggedInUserId, updateData);

        res.json({ message: "User updated successfully" });
    } catch (error) {
        console.error("Update User Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const loggedInUserId = decoded.userId;

        if (!id) return res.status(400).json({ message: "User ID is required" });
        await UserModel.deleteUser(loggedInUserId, id);
        res.json({ message: "User deleted successfully" });
    } catch (error) {
        console.error("Delete User Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendOtpEmail = async (email, otpCode, purpose) => {
    let subject, text;
    
    switch(purpose) {
        case "login":
            subject = "Your Login OTP Code";
            text = `Your OTP code for login is: ${otpCode}\nThis code expires in 10 minutes.`;
            break;
        case "registration":
            subject = "Your Registration OTP Code";
            text = `Your OTP code for registration is: ${otpCode}\nThis code expires in 10 minutes.`;
            break;
        case "password_reset":
            subject = "Your Password Reset Code";
            text = `Your password reset OTP code is: ${otpCode}\nThis code expires in 10 minutes.`;
            break;
        default:
            subject = "Your OTP Code";
            text = `Your OTP code is: ${otpCode}\nThis code expires in 10 minutes.`;
    }

    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject,
        text
    });
};
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "All fields are required" });

        const user = await UserModel.getUserByEmail(email);
        if (!user) return res.status(400).json({ message: "Invalid credentials" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });
        const otpCode = await OtpModel.createOtp(user.id, user.email, "login");
        await sendOtpEmail(user.email, otpCode, "login");

        res.json({ 
            message: "OTP sent to your registered email", 
            userId: user.id,
            requiresOtp: true
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const verifyLoginOtp = async (req, res) => {
    try {
        const { userId, otpCode } = req.body;
        
        const now = new Date();
        const nowUTC = new Date(now.toISOString());
        
        const [otpRecord] = await db.query(
            `SELECT *, UTC_TIMESTAMP() as current_db_time 
             FROM tbl_otps 
             WHERE user_id = ? 
             AND otp_code = ? 
             AND purpose = 'login'`,
            [userId, otpCode]
        );

        if (!otpRecord.length) {
            return res.status(400).json({ message: "Invalid OTP code" });
        }

        const otp = otpRecord[0];
        const expiresAt = new Date(otp.expires_at);
        
        if (nowUTC > expiresAt) {
            await db.query(`DELETE FROM tbl_otps WHERE id = ?`, [otp.id]);
            return res.status(400).json({ message: "OTP expired" });
        }

        await db.query(`DELETE FROM tbl_otps WHERE id = ?`, [otp.id]);
        
        const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "24h" });
        await UserModel.createSession(userId, token, req.ip, req.headers["user-agent"]);

        res.json({ 
            message: "Login successful", 
            token 
        });
    } catch (error) {
        console.error("OTP Verification Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};
const signup = async (req, res) => {
    try {
        const { username, password, email, firstName, lastName, middleName, phoneNumber } = req.body;
        console.log("Session Data:", req.session);

        if (!username || !password || !email || !firstName || !lastName) {
            return res.status(400).json({ message: "All required fields must be filled" });
        }
        const existingUser = await UserModel.getUserByEmail(email);
        if (existingUser) return res.status(400).json({ message: "Email already exists" });

        const [emailCheck] = await db.query("SELECT id FROM tbl_users WHERE email = ?", [email]);
        if (emailCheck.length > 0) return res.status(400).json({ message: "Email already registered" });
        
        req.session.tempUser = {
            username,
            password,
            email,
            firstName,
            middleName,
            lastName,
            phoneNumber
        };

        console.log("Session Data:", req.session);

        const otpCode = await OtpModel.createOtp(null, email, "registration");
        await sendOtpEmail(email, otpCode, "registration");

        res.json({ 
            message: "OTP sent to your email for verification",
            requiresOtp: true
        });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const verifySignupOtp = async (req, res) => {
    try {
        const { email, otpCode, username, password, firstName, middleName, lastName, phoneNumber } = req.body;
        
        if (!email || !otpCode) {
            return res.status(400).json({ message: "Email and OTP code are required" });
        }

        const [otpRecord] = await db.query(
            `SELECT * FROM tbl_otps 
             WHERE email = ? 
             AND otp_code = ? 
             AND purpose = 'registration'
             AND (user_id IS NULL OR user_id = 0)`,
            [email, otpCode]
        );

        if (!otpRecord.length) {
            return res.status(400).json({ message: "OTP not found" });
        }

        const otp = otpRecord[0];
        const now = new Date();
        const expiresAt = new Date(otp.expires_at);

        if (now > expiresAt) {
            await db.query(`DELETE FROM tbl_otps WHERE id = ?`, [otp.id]);
            return res.status(400).json({ message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = await UserModel.createUser({
            username,
            password: hashedPassword,
            email,
            firstName,
            middleName: middleName || "",
            lastName,
            phoneNumber: phoneNumber || null,
        });

        await db.query(
            "UPDATE tbl_otps SET user_id = ? WHERE id = ?",
            [userId, otp.id]
        );

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Signup OTP Verification Error:", error);
        res.status(500).json({ 
            message: "Server error", 
            error: error.message
        });
    }
};

const requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        const user = await UserModel.getUserByEmail(email);
        if (!user) {
            return res.json({ 
                message: "If this email is registered, you'll receive a password reset OTP"
            });
        }

        const otpCode = await OtpModel.createOtp(user.id, user.email, "password_reset");
        await sendOtpEmail(user.email, otpCode, "password_reset");

        res.json({ 
            message: "OTP sent to your email",
            userId: user.id,
            requiresOtp: true
        });

    } catch (error) {
        console.error("Password reset request error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const verifyPasswordReset = async (req, res) => {
    try {
        const { userId, otpCode, newPassword } = req.body;
        
        if (!userId || !otpCode || !newPassword) {
            return res.status(400).json({ 
                message: "User ID, OTP code and new password are required" 
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ 
                message: "Password must be at least 8 characters" 
            });
        }

        const isValid = await OtpModel.verifyOtp(userId, otpCode, "password_reset");
        if (!isValid) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query(
            "UPDATE tbl_users SET password = ? WHERE id = ?",
            [hashedPassword, userId]
        );

        await OtpModel.invalidateOtp(otpCode);

        res.json({ 
            message: "Password reset successful" 
        });

    } catch (error) {
        console.error("Password reset verification error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const resendOtp = async (req, res) => {
    try {
        const { email, purpose } = req.body;
        
        if (!email || !purpose) {
            return res.status(400).json({ 
                success: false,
                message: "Email and purpose are required",
                code: "MISSING_FIELDS"
            });
        }

        const validPurposes = ["login", "registration", "password_reset"];
        if (!validPurposes.includes(purpose)) {
            return res.status(400).json({ 
                success: false,
                message: "Invalid purpose",
                code: "INVALID_PURPOSE"
            });
        }

        if (purpose === "registration") {
            const [existingRegistration] = await db.query(
                `SELECT 1 FROM tbl_otps 
                 WHERE email = ? 
                 AND purpose = 'registration'
                 AND expires_at > NOW() 
                 LIMIT 1`,
                [email]
            );

            if (!existingRegistration.length) {
                return res.status(400).json({ 
                    success: false,
                    message: "No active registration found. Please start over.",
                    code: "NO_REGISTRATION"
                });
            }
        }

        await db.query(
            `DELETE FROM tbl_otps 
             WHERE email = ? 
             AND purpose = ?`,
            [email, purpose]
        );

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        
        await db.query(
            `INSERT INTO tbl_otps 
             (email, otp_code, purpose, expires_at, created_at) 
             VALUES (?, ?, ?, ?, NOW())`,
            [email, otpCode, purpose, expiresAt]
        );

        await sendOtpEmail(email, otpCode, purpose);

        return res.json({ 
            success: true,
            message: "New OTP sent successfully",
            debugCode: process.env.NODE_ENV === "development" ? otpCode : undefined
        });

    } catch (error) {
        console.error("Resend OTP Error:", {
            error: error.message,
            stack: error.stack,
            timestamp: new Date()
        });
        
        return res.status(500).json({ 
            success: false,
            message: "Internal server error",
            code: "SERVER_ERROR"
        });
    }
};
const profile = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await UserModel.getUserById(decoded.userId);

        console.log("user", user);

        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({ user });
    } catch (error) {
        console.error("Profile Error:", error);
        res.status(401).json({ message: "Invalid token" });
    }
};

const logout = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(400).json({ message: "No token provided" });

        const session = await UserModel.getSessionByToken(token);
        if (!session) return res.status(400).json({ message: "Invalid session or already logged out" });

        await UserModel.expireSession(token);

        res.json({ message: "Logout successful" });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};


module.exports = {
    getAllUsers,
    createUser,
    updateUser,
    deleteUser,
    login,
    verifyLoginOtp,
    signup,
    verifySignupOtp,
    requestPasswordReset,
    verifyPasswordReset,
    resendOtp,
    logout,
    profile
};

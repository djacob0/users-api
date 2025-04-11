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

const updateUser = async () => {
    if (!selectedUser.username || !selectedUser.email || !selectedUser.firstName || !selectedUser.lastName) {
        Swal.fire({
            icon: "error",
            title: "Missing Fields",
            text: "Please fill in all required fields!",
        });
        return;
    }

    const token = localStorage.getItem("authToken");
    if (!token) {
        Swal.fire({ icon: "error", title: "Unauthorized", text: "Authentication token not found. Please log in." });
        return;
    }

    try {
        const response = await api.put(`/api/users-by-approver/${selectedUser.id}`, selectedUser, {
            headers: { Authorization: `Bearer ${token}` },
        });

        setIsModalOpen(false);
        setSelectedUser(null);
        fetchUsers();

        Swal.fire({ 
            icon: "success", 
            title: "User Updated", 
            text: "User successfully updated!",
            timer: 2000, 
            showConfirmButton: false 
        });
    } catch (error) {
        console.error("Error updating user:", error.response?.data || error.message);
        
        let errorMessage = "Error updating user.";
        if (error.response?.data?.error === "DUPLICATE_USERNAME") {
            errorMessage = "Username already exists. Please choose a different username.";
        } else if (error.response?.data?.message) {
            errorMessage = error.response.data.message;
        }

        Swal.fire({ 
            icon: "error", 
            title: "Error", 
            text: errorMessage
        });
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

        if (user.status === "PENDING" || user.status === "REJECTED") {
            return res.status(403).json({
                message: "Your account is not approved. Please wait for approval or contact an administrator.",
                requiresApproval: true
            });
        }

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

        if (!username || !password || !email || !firstName || !lastName) {
            return res.status(400).json({ message: "All required fields must be filled" });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters long" });
        }
        
        if (!/[A-Z]/.test(password)) {
            return res.status(400).json({ message: "Password must contain at least one capital letter" });
        }
        
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            return res.status(400).json({ message: "Password must contain at least one special character" });
        }
        
        const existingUser = await UserModel.getUserByEmail(email);
        if (existingUser) return res.status(400).json({ message: "Email already exists" });

        const otpCode = await OtpModel.createOtp(null, email, "registration");
        await sendOtpEmail(email, otpCode, "registration");

        await db.query(
            `INSERT INTO temp_signups 
             (username, password, email, first_name, last_name, middle_name, phone_number, otp_code)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [username, password, email, firstName, lastName, middleName || null, phoneNumber || null, otpCode]
        );

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
        const { email, otpCode } = req.body;
        
        if (!email || !otpCode) {
            return res.status(400).json({ message: "Email and OTP code are required" });
        }

        const [tempUser] = await db.query(
            `SELECT * FROM temp_signups 
             WHERE email = ? AND otp_code = ?`,
            [email, otpCode]
        );

        if (!tempUser.length) {
            return res.status(400).json({ message: "Invalid OTP code" });
        }

        const userData = tempUser[0];
        const hashedPassword = await bcrypt.hash(userData.password, 10);

        const userId = await UserModel.createUser({
            username: userData.username,
            password: hashedPassword,
            email: userData.email,
            firstName: userData.first_name,
            lastName: userData.last_name,
            middleName: userData.middle_name,
            phoneNumber: userData.phone_number,
            isApproved: false,
            status: 'PENDING',
            accountLevel: 3
        });

        await db.query(`DELETE FROM temp_signups WHERE email = ?`, [email]);

        res.status(201).json({ 
            message: "Registration successful. Your account is pending admin approval.",
            requiresApproval: true
        });
    } catch (error) {
        console.error("Signup OTP Verification Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
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

const updateUserProfile = async (req, res) => {
    try {
        const userId = req.params.id;
        const { phoneNumber, firstName, lastName, email } = req.body;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const requester = await UserModel.getUserById(decoded.userId);

        if (requester.id !== parseInt(userId)){
            return res.status(403).json({ message: "Can only update your own profile" });
        }

        const updateData = {
            id: userId,
            phoneNumber,
            firstName,
            lastName,
            email,
            updated_at: new Date()
        };

        await UserModel.updateUserProfile(updateData);
        res.json({ message: "Profile updated successfully" });
    } catch (error) {
        console.error("Profile update error:", error);
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
    profile,
    updateUserProfile
};

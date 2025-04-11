const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const UserModel = require("../models/UserModel");
const OtpModel = require("../models/OtpModel");
const nodemailer = require("nodemailer");
require("dotenv").config();
const db = require("../config/db");

const getPendingApprovals = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await UserModel.getUserById(decoded.userId);

        if (user.accountLevel > 2) {
            return res.status(403).json({ message: "Unauthorized access" });
        }

        const pendingUsers = await UserModel.getPendingApprovals();
        res.json({ pendingUsers });
    } catch (error) {
        console.error("Get Pending Approvals Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const approveUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const approver = await UserModel.getUserById(decoded.userId);

        if (approver.accountLevel > 2) {
            return res.status(403).json({ message: "Unauthorized access" });
        }

        await UserModel.approveUser(userId, decoded.userId);
        res.json({ message: "User approved successfully" });
    } catch (error) {
        console.error("Approve User Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const rejectUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const approver = await UserModel.getUserById(decoded.userId);

        if (approver.accountLevel > 2) {
            return res.status(403).json({ message: "Unauthorized access" });
        }

        await UserModel.rejectUser(userId, decoded.userId);
        res.json({ message: "User rejected successfully" });
    } catch (error) {
        console.error("Reject User Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const getUsersByApprover = async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const approver = await UserModel.getUserById(decoded.userId);
        if (approver.accountLevel > 2 && ![1, 2].includes(approver.id)) {
            return res.status(403).json({ message: "Forbidden: Insufficient privileges" });
        }
        const users = await UserModel.getAllUsers();

        const sanitizedUsers = users.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            status: user.status,
            accountLevel: user.accountLevel,
            createdAt: user.created_at
        }));

        res.json({ users: sanitizedUsers });
    } catch (error) {
        console.error("Get Users by Approver Error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

const updateUserByApprover = async (req, res) => {
    try {
        const userIdToUpdate = req.params.id;
        const { status, accountLevel } = req.body;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const approver = await UserModel.getUserById(decoded.userId);
        const targetUser = await UserModel.getUserById(userIdToUpdate);

        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        if (approver.accountLevel === 1) {
        } 
        else if (approver.accountLevel === 2) {
            if (targetUser.accountLevel === 1) {
                return res.status(403).json({ 
                    message: "Forbidden: Admins cannot modify developers" 
                });
            }
        }
        else {
            return res.status(403).json({ 
                message: "Forbidden: Insufficient privileges" 
            });
        }

        if (accountLevel === 1 && approver.accountLevel !== 1) {
            return res.status(403).json({ 
                message: "Forbidden: Only developers can create other developers" 
            });
        }

        if (targetUser.accountLevel === 1 && accountLevel !== 1) {
            return res.status(403).json({ 
                message: "Forbidden: Cannot demote developers" 
            });
        }

        const updateData = {
            id: userIdToUpdate,
            status: status,
            accountLevel: accountLevel,
            updated_by: approver.id,
            updated_at: new Date(),
        };

        await UserModel.updateUser(updateData);
        res.json({ 
            message: "User updated successfully",
            updatedUserId: userIdToUpdate,
            updatedBy: approver.id,
            newStatus: status,
            newAccountLevel: accountLevel
        });
    } catch (error) {
        console.error("Update User by Approver Error:", error);
        res.status(500).json({ 
            message: "Server error", 
            error: error.message 
        });
    }
};

module.exports = {
    getPendingApprovals,
    approveUser,
    rejectUser,
    getUsersByApprover,
    updateUserByApprover
};
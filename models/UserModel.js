const db = require("../config/db");
const bcrypt = require("bcryptjs");

const UserModel = {
    createUser: async (userData) => {
        const requiredFields = ["username", "password", "email", "firstName", "lastName"];
        for (const field of requiredFields) {
            if (!userData[field]) {
                throw new Error(`Field "${field}" cannot be null or empty.`);
            }
        }

        userData.status = userData.status || "active";
        userData.accountLevel = userData.accountLevel || 1;
        userData.created_at = new Date();
        userData.created_by = 1;

        const columns = Object.keys(userData).map((key) => `\`${key}\``).join(", ");
        const placeholders = Object.keys(userData).map(() => "?").join(", ");
        const values = Object.values(userData);

        const query = `INSERT INTO tbl_users (${columns}) VALUES (${placeholders})`;

        const [result] = await db.query(query, values);
        return result.insertId;
    },

    checkApprovalStatus: async (userId) => {
        const [user] = await db.query(
            "SELECT isApproved FROM tbl_users WHERE id = ?", 
            [userId]
        );
        return user.length ? user[0].isApproved : false;
    },

    updatePassword: async (userId, newPassword) => {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query(
            "UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?",
            [hashedPassword, userId]
        );
    },

    getUserByEmail: async (email) => {
        const [user] = await db.query("SELECT * FROM tbl_users WHERE email = ?", [email]);
        return user.length ? user[0] : null;
    },

    getUserById: async (id) => {
        const [user] = await db.query("SELECT * FROM tbl_users WHERE id = ?", [id]);
        return user.length ? user[0] : null;
    },

    createSession: async (userId, token, ipAddress, userAgent) => {
        const createdAt = new Date();
        const expiresAt = new Date(createdAt.getTime() + 24 * 60 * 60 * 1000);
        
        await db.query(
            `INSERT INTO tbl_sessions 
             (user_id, session_token, ip_address, user_agent, status, created_at, expires_at) 
             VALUES (?, ?, ?, ?, 'active', ?, ?)`,
            [userId, token, ipAddress, userAgent, createdAt, expiresAt]
        );
    },

    expireSession: async (token) => {
        await db.query(
            "UPDATE tbl_sessions SET status = 'expired', logout_time = NOW() WHERE session_token = ?",
            [token]
        );
    },

    getSessionByToken: async (token) => {
        const [session] = await db.query(
            "SELECT * FROM tbl_sessions WHERE session_token = ? AND status = 'active' AND expires_at > NOW()", 
            [token]
        );
        
        return session.length ? session[0] : null;
    },

    getAllUsers: async () => {
        const query = "SELECT id, username, email, firstName, middleName, lastName, accountLevel, phoneNumber, status FROM tbl_users";
        const [users] = await db.query(query);
        return users;
    },

    createUser: async (userData, userId) => {
        const requiredFields = ["username", "password", "email", "firstName", "lastName"];
        for (const field of requiredFields) {
            if (!userData[field]) {
                throw new Error(`Field "${field}" cannot be null or empty.`);
            }
        }

        userData.status = userData.status || "active";
        userData.accountLevel = userData.accountLevel || 1;
        userData.created_at = new Date();
        userData.created_by = userId; 
        userData.updated_at = new Date();
        userData.updated_by = userId;

        const columns = Object.keys(userData).map((key) => `\`${key}\``).join(", ");
        const placeholders = Object.keys(userData).map(() => "?").join(", ");
        const values = Object.values(userData);

        const query = `INSERT INTO tbl_users (${columns}) VALUES (${placeholders})`;

        const [result] = await db.query(query, values);
        return result.insertId;
    },

    updateUser: async (userId, userData) => {
        try {
            if (!userData || Object.keys(userData).length === 0) {
                throw new Error("No data to update");
            }
    
            const updates = Object.keys(userData)
                .map((key) => `${key} = ?`)
                .join(", ");
            const values = [...Object.values(userData), userData.id];
            const query = `UPDATE tbl_users SET ${updates} WHERE id = ?`;
    
            await db.query(query, values);
        } catch (error) {
            throw new Error("Error updating user: " + error.message);
        }
    },

    deleteUser: async (userId, targetUserId) => {
        if (!targetUserId) throw new Error("Target user ID is required");

        const query = `DELETE FROM tbl_users WHERE id = ? AND id != ?`;
        await db.query(query, [targetUserId, userId]);
    },

    // this is for account levels

    getUserWithLevel: async (userId) => {
        const [users] = await db.query(`
            SELECT u.*, al.name as levelName, al.description as levelDescription 
            FROM tbl_users u
            LEFT JOIN tbl_account_level al ON u.accountLevel = al.id
            WHERE u.id = ?
        `, [userId]);
        return users[0];
    },

    getPendingApprovals: async () => {
        const [users] = await db.query(`
            SELECT u.*, al.name as levelName 
            FROM tbl_users u
            LEFT JOIN tbl_account_level al ON u.accountLevel = al.id
            WHERE u.isApproved = 0
        `);
        return users;
    },

    approveUser: async (userId, approverId) => {
        await db.query(`
            UPDATE tbl_users 
            SET isApproved = 1, 
                updated_by = ?,
                updated_at = NOW()
            WHERE id = ?
        `, [approverId, userId]);
    },

    rejectUser: async (userId, approverId) => {
        await db.query(`
            UPDATE tbl_users 
            SET isApproved = 0,
                status = 'REJECTED',
                updated_by = ?,
                updated_at = NOW()
            WHERE id = ?
        `, [approverId, userId]);
    },

    updateAccountLevel: async (userId, levelId, updaterId) => {
        await db.query(`
            UPDATE tbl_users 
            SET accountLevel = ?,
                updated_by = ?,
                updated_at = NOW()
            WHERE id = ?
        `, [levelId, updaterId, userId]);
    }
    
};

module.exports = UserModel;

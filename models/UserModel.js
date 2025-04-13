const db = require("../config/db");
const bcrypt = require("bcryptjs");

const UserModel = {

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

    createUser: async (userData) => {
        const requiredFields = ["username", "password", "email", "firstName", "lastName"];
        for (const field of requiredFields) {
            if (!userData[field]) {
                throw new Error(`Field "${field}" cannot be null or empty.`);
            }
        }

        const defaultValues = {
            status: 'PENDING',
            accountLevel: 3,
            isApproved: false,
            created_at: new Date(),
            updated_at: new Date()
        };

        const finalUserData = { ...defaultValues, ...userData };

        const columns = Object.keys(finalUserData).map(key => `\`${key}\``).join(", ");
        const placeholders = Object.keys(finalUserData).map(() => "?").join(", ");
        const values = Object.values(finalUserData);

        const [result] = await db.query(
            `INSERT INTO tbl_users (${columns}) VALUES (${placeholders})`,
            values
        );

        return result.insertId;
    },

    updateUser: async (updateData) => {
        const { id, status, accountLevel, updated_by, updated_at } = updateData;
        
        const [result] = await db.query(
            `UPDATE tbl_users 
             SET status = ?,
                 accountLevel = ?,
                 updated_by = ?,
                 updated_at = ?
             WHERE id = ?`,
            [status, accountLevel, updated_by, updated_at, id]
        );
        
        return result;
    },

    deleteUser: async (userId, targetUserId) => {
        if (!targetUserId) throw new Error("Target user ID is required");

        const query = `DELETE FROM tbl_users WHERE id = ? AND id != ?`;
        await db.query(query, [targetUserId, userId]);
    },

    // generateMFAToken: async (userId) => {
    //     const token = Buffer.from(`${userId}:${Date.now()}`).toString('base64');
    //     await db.query(
    //         `UPDATE tbl_users SET mfa_token = ?, mfa_token_expires = DATE_ADD(NOW(), INTERVAL 5 MINUTE) WHERE id = ?`,
    //         [token, userId]
    //     );
    //     return token;
    // },

    // verifyMFAToken: async (userId, token) => {
    //     const [result] = await db.query(
    //         `SELECT mfa_token, mfa_token_expires 
    //         FROM tbl_users 
    //         WHERE id = ? 
    //         AND mfa_token = ?
    //         AND mfa_token_expires > NOW()`,
    //         [userId, token]
    //     );
    //     return result.length > 0;
    // },

    // clearMFAToken: async (userId) => {
    //     await db.query(
    //         `UPDATE tbl_users SET mfa_token = NULL, mfa_token_expires = NULL WHERE id = ?`,
    //         [userId]
    //     );
    // },

    // this is for account levels

    // In UserModel.js
    getUsersByAccountLevels: async (levels) => {
        const [users] = await db.query(
            `SELECT id, username, email, firstName, lastName, 
                    status, accountLevel, created_at 
             FROM tbl_users 
             WHERE accountLevel IN (?) 
             AND username != 'system'
             ORDER BY accountLevel, created_at`,
            [levels]
        );
        return users;
    },

    getAllNonSystemUsers: async () => {
        const [users] = await db.query(
            `SELECT id, username, email, firstName, lastName, 
                    status, accountLevel, created_at 
             FROM tbl_users 
             WHERE username != 'system' 
             ORDER BY accountLevel, created_at`
        );
        return users;
    },

    updateUserProfile: async (updateData) => {
        const { id, phoneNumber, firstName, lastName, email, updated_at } = updateData;
        
        const [result] = await db.query(
            `UPDATE tbl_users 
            SET phoneNumber = ?,
                firstName = ?,
                lastName = ?,
                email = ?,
                updated_at = ?
            WHERE id = ?`,
            [phoneNumber, firstName, lastName, email, updated_at, id]
        );
        
        return result;
    },

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
            WHERE u.isApproved = 0 AND u.status = 'PENDING'
        `);
        return users;
    },

    approveUser: async (userId, approverId) => {
        await db.query(`
            UPDATE tbl_users 
            SET isApproved = 1, 
                status = 'APPROVED',
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

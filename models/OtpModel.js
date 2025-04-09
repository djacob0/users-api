const db = require("../config/db");
const crypto = require("crypto");

const OtpModel = {
    createOtp: async (userId, email, purpose) => {
        await db.query(
            `UPDATE tbl_otps 
             SET expires_at = NOW() 
             WHERE email = ? 
             AND purpose = ?
             AND expires_at > NOW()`,
            [email, purpose]
        );

        const otpCode = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 10);
        
        await db.query(
            `INSERT INTO tbl_otps (user_id, otp_code, email, purpose, expires_at)
             VALUES (?, ?, ?, ?, ?)`,
            [userId, otpCode, email, purpose, expiresAt]
        );
        
        return otpCode;
    },

    verifyOtp: async (userId, otpCode, purpose) => {
        const [otp] = await db.query(
            `SELECT * FROM tbl_otps 
             WHERE (user_id = ? OR email IN (SELECT email FROM tbl_users WHERE id = ?))
             AND otp_code = ? 
             AND purpose = ? 
             AND expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1`,
            [userId, userId, otpCode, purpose]
        );

        if (otp.length > 0) {
            await db.query(
                `UPDATE tbl_otps 
                 SET expires_at = NOW() 
                 WHERE id = ?`,
                [otp[0].id]
            );
            return true;
        }
        return false;
    },

    invalidateOtp: async (otpCode) => {
        await db.query(
            `UPDATE tbl_otps 
             SET expires_at = NOW() 
             WHERE otp_code = ?`,
            [otpCode]
        );
    },

    cleanupExpiredOtps: async () => {
        await db.query(
            `DELETE FROM tbl_otps WHERE expires_at <= NOW()`
        );
    }
};

module.exports = OtpModel;
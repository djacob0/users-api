const db = require("../config/db");
const crypto = require("crypto");

const OtpModel = {
    // Generate and store OTP
    createOtp: async (userId, email, purpose) => {
        const otpCode = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 10); // 10 minutes expiration
        
        await db.query(
            `INSERT INTO tbl_otps (user_id, otp_code, email, purpose, expires_at)
             VALUES (?, ?, ?, ?, ?)`,
            [userId, otpCode, email, purpose, expiresAt]
        );
        
        return otpCode;
    },
    // Verify OTP
    verifyOtp: async (userId, otpCode, purpose) => {
        const [otp] = await db.query(
            `SELECT * FROM tbl_otps 
             WHERE user_id = ? AND otp_code = ? AND purpose = ? 
             AND expires_at > NOW()`,
            [userId, otpCode, purpose]
        );

        return otp.length > 0;
    },

    // Invalidate OTP after use
    invalidateOtp: async (otpCode) => {
        await db.query(
            `DELETE FROM tbl_otps WHERE otp_code = ?`,
            [otpCode]
        );
    },

    // Clean up expired OTPs
    cleanupExpiredOtps: async () => {
        await db.query(
            `DELETE FROM tbl_otps WHERE expires_at <= NOW()`
        );
    }
};

module.exports = OtpModel;
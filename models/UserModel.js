const pool = require("../config/db");

class UserModel {

    static async getUserByUsername(username) {
        const [rows] = await pool.query("SELECT * FROM tbl_users WHERE username = ?", [username]);
        return rows[0];
      }
      
    static async getAllUsers() {
      const [rows] = await pool.query("SELECT * FROM tbl_users");
      return rows;
    }
  
    static async getUserById(id) {
      const [rows] = await pool.query("SELECT * FROM tbl_users WHERE id = ?", [id]);
      return rows[0];
    }
  
    static async createUser(user) {
        const userData = {
          ...user,
          created_by: user.created_by || 1, 
          updated_at: null, 
          updated_by: null  
        };
      
        const fields = Object.keys(userData).join(", ");
        const placeholders = Object.keys(userData).map(() => "?").join(", ");
        const values = Object.values(userData);
      
        const [result] = await pool.query(
          `INSERT INTO tbl_users (${fields}) VALUES (${placeholders})`,
          values
        );
      
        return result.insertId;
      }      

      static async updateUser(id, userData) {
        const updatedBy = userData.updated_by || "SYSTEM";
        const updatedAt = new Date();
    
        const [result] = await pool.query(
            `UPDATE tbl_users SET updated_by = ?, updated_at = ? WHERE id = ?`,
            [updatedBy, updatedAt, id]
        );
    
        return result.affectedRows > 0;
    }
      

      static async deleteUser(id) {
        const [result] = await pool.query("DELETE FROM tbl_users WHERE id = ?", [id]);
        return result.affectedRows;
      }

      static async createSession(userId, token, ipAddress, userAgent) {
        const [result] = await pool.query(
            "INSERT INTO tbl_sessions (user_id, session_token, ip_address, user_agent, status) VALUES (?, ?, ?, ?, 'active')",
            [userId, token, ipAddress, userAgent]
        );
        return result.insertId;
    }

    static async getSession(token) {
        const [rows] = await pool.query("SELECT * FROM tbl_sessions WHERE session_token = ? AND status = 'active'", [token]);
        return rows[0];
    }

    static async expireSession(token) {
        const [result] = await pool.query(
            "UPDATE tbl_sessions SET status = 'expired', logout_time = NOW() WHERE session_token = ?",
            [token]
        );
        return result.affectedRows > 0;
    }
  }

  

  
  module.exports = UserModel;
  
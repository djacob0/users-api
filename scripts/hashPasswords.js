const bcrypt = require("bcryptjs");
const db = require("../config/db"); 

async function hashExistingPasswords() {
  try {
    const [users] = await db.query("SELECT id, password FROM users");

    for (let user of users) {
      if (!user.password.startsWith("$2a$")) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        
        await db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, user.id]);
      }
    }

    console.log("All passwords hashed!");
  } catch (error) {
    console.error("Error hashing passwords:", error);
  }
}

hashExistingPasswords();

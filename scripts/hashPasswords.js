const bcrypt = require("bcryptjs");
const db = require("../config/db"); 

async function hashExistingPasswords() {
  try {
    // Get users from the database
    const [users] = await db.query("SELECT id, password FROM users");

    for (let user of users) {
      // Check if the password is not already hashed
      if (!user.password.startsWith("$2a$")) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        
        // Update the password in the database
        await db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, user.id]);
      }
    }

    console.log("All passwords hashed!");
  } catch (error) {
    console.error("Error hashing passwords:", error);
  }
}

hashExistingPasswords();

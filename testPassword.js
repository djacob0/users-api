const bcrypt = require("bcrypt");

const enteredPassword = "test35"; // The password you're entering
const storedHash = "$2b$10$RDUYb4IHrVcndx/dsV2oquWSnyN/Y3kjNB5E.02LFUAOPZUdTDNDW"; // From your database

bcrypt.compare(enteredPassword, storedHash)
    .then(result => console.log("Password match:", result ? "✅ MATCH" : "❌ NO MATCH"))
    .catch(err => console.error("Error comparing passwords:", err));

const bcrypt = require("bcrypt");

const enteredPassword = "test35";
const storedHash = "$2b$10$RDUYb4IHrVcndx/dsV2oquWSnyN/Y3kjNB5E.02LFUAOPZUdTDNDW";

bcrypt.compare(enteredPassword, storedHash)
    .then(result => console.log("Password match:", result ? "tama" : "mali"))
    .catch(err => console.error("Error comparing passwords:", err));

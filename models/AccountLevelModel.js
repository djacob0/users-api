// const db = require("../config/db");

// const AccountLevelModel = {
//     getAllLevels: async () => {
//         const [levels] = await db.query("SELECT * FROM tbl_account_level");
//         return levels;
//     },

//     getLevelById: async (id) => {
//         const [level] = await db.query("SELECT * FROM tbl_account_level WHERE id = ?", [id]);
//         return level[0];
//     },

//     getDefaultLevel: async () => {
//         const [level] = await db.query("SELECT * FROM tbl_account_level WHERE id = 3");
//         return level[0];
//     }
// };

// module.exports = AccountLevelModel;
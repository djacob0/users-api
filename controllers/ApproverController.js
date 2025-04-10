// const UserModel = require("../models/UserModel");
// const jwt = require("jsonwebtoken");
// require("dotenv").config();

// const ApproverController = {
//     getPendingApprovals: async (req, res) => {
//         try {
//             const token = req.headers.authorization?.split(" ")[1];
//             if (!token) return res.status(401).json({ message: "Unauthorized" });

//             const decoded = jwt.verify(token, process.env.JWT_SECRET);
//             const approver = await UserModel.getUserById(decoded.userId);

//             // Check if approver has permission (Developer or Admin)
//             if (approver.accountLevel !== 1 && approver.accountLevel !== 2) {
//                 return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
//             }

//             const pendingUsers = await UserModel.getPendingApprovals();
//             res.json({ pendingUsers });
//         } catch (error) {
//             console.error("Get Pending Approvals Error:", error);
//             res.status(500).json({ message: "Server error", error: error.message });
//         }
//     },

//     approveUser: async (req, res) => {
//         try {
//             const { userId } = req.params;
//             const token = req.headers.authorization?.split(" ")[1];
//             if (!token) return res.status(401).json({ message: "Unauthorized" });

//             const decoded = jwt.verify(token, process.env.JWT_SECRET);
//             const approver = await UserModel.getUserById(decoded.userId);

//             // Check if approver has permission
//             if (approver.accountLevel !== 1 && approver.accountLevel !== 2) {
//                 return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
//             }

//             await UserModel.approveUser(userId, decoded.userId);
//             res.json({ message: "User approved successfully" });
//         } catch (error) {
//             console.error("Approve User Error:", error);
//             res.status(500).json({ message: "Server error", error: error.message });
//         }
//     },

//     rejectUser: async (req, res) => {
//         try {
//             const { userId } = req.params;
//             const token = req.headers.authorization?.split(" ")[1];
//             if (!token) return res.status(401).json({ message: "Unauthorized" });

//             const decoded = jwt.verify(token, process.env.JWT_SECRET);
//             const approver = await UserModel.getUserById(decoded.userId);

//             // Check if approver has permission
//             if (approver.accountLevel !== 1 && approver.accountLevel !== 2) {
//                 return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
//             }

//             await UserModel.rejectUser(userId, decoded.userId);
//             res.json({ message: "User rejected successfully" });
//         } catch (error) {
//             console.error("Reject User Error:", error);
//             res.status(500).json({ message: "Server error", error: error.message });
//         }
//     },

//     updateUserLevel: async (req, res) => {
//         try {
//             const { userId } = req.params;
//             const { levelId } = req.body;
//             const token = req.headers.authorization?.split(" ")[1];
//             if (!token) return res.status(401).json({ message: "Unauthorized" });

//             const decoded = jwt.verify(token, process.env.JWT_SECRET);
//             const updater = await UserModel.getUserById(decoded.userId);

//             // Only Developers can change account levels
//             if (updater.accountLevel !== 1) {
//                 return res.status(403).json({ message: "Forbidden: Only developers can change account levels" });
//             }

//             await UserModel.updateAccountLevel(userId, levelId, decoded.userId);
//             res.json({ message: "Account level updated successfully" });
//         } catch (error) {
//             console.error("Update Account Level Error:", error);
//             res.status(500).json({ message: "Server error", error: error.message });
//         }
//     }
// };

// module.exports = ApproverController;
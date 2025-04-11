const express = require("express");
const ApproverController = require("../controllers/ApproverController");
const router = express.Router();

router.get("/pending-approvals", ApproverController.getPendingApprovals);
router.put("/approve-user/:userId", ApproverController.approveUser);
router.put("/reject-user/:userId", ApproverController.rejectUser);
router.get("/users-by-approver", ApproverController.getUsersByApprover);
router.put("/users-by-approver/:id", ApproverController.updateUserByApprover);

module.exports = router;
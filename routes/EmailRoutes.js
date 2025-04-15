const express = require('express');
const router = express.Router();
const emailController = require('../controllers/emailController');
const multer = require('multer');
const upload = multer();

router.post('/send-validation-results', 
  upload.fields([
    { name: 'validFile', maxCount: 1 },
    { name: 'invalidFile', maxCount: 1 }
  ]),
  emailController.sendValidationResults
);

module.exports = router;
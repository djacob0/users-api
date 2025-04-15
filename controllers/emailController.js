const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

exports.sendValidationResults = async (req, res) => {
  try {
    const { recipient, subject, message } = req.body;
    
    if (!recipient) {
      return res.status(400).json({ 
        success: false, 
        message: 'Recipient email is required' 
      });
    }

    const attachments = [];
    
    if (req.files?.validFile) {
        const filename = req.body.validFileName || 'valid_data.xlsx';
        attachments.push({
          filename: filename,
          content: req.files.validFile[0].buffer
        });
      }
  
      if (req.files?.invalidFile) {
        const filename = req.body.invalidFileName || 'invalid_data.xlsx';
        attachments.push({
          filename: filename,
          content: req.files.invalidFile[0].buffer
        });
      }

    if (attachments.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No files selected for sending' 
      });
    }

    const mailOptions = {
      from: `"Data Cleanup Self Service" <${process.env.EMAIL_FROM}>`,
      to: recipient,
      subject: subject || 'Data Validation Results',
      text: message || 'Please find attached the validation results for your data.',
      attachments: attachments
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      success: true, 
      message: 'Email sent successfully' 
    });
  } catch (error) {
    console.error('Email sending error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send email',
      error: error.message 
    });
  }
};
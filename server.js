require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const sessionMiddleware = require("./middleware/authMiddleware");

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(sessionMiddleware);

const userRoutes = require("./routes/userRoutes");
app.use("/api", userRoutes); 

app.use((err, req, res, next) => {
    console.error("Server Error:", err);
    res.status(500).json({ message: "Internal Server Error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

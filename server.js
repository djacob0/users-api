require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const session = require("express-session");

const app = express();

app.use(cors());
app.use(bodyParser.json());

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false },
    })
);

const UserRoutes = require("./routes/UserRoutes");
const ApproverRoutes = require("./routes/ApproverRoutes");
const EmailRoutes = require('./routes/EmailRoutes');
// const FFRSAuthRoute = require("./routes/FFRSAuthRoute");
// app.use("/api", FFRSAuthRoute);
app.use("/api", ApproverRoutes);
app.use("/api", UserRoutes);
app.use('/api/email', EmailRoutes);

app.get("/", (req, res) => res.send("API is running..."));

app.use((err, req, res, next) => {
    console.error("Server Error:", err);
    res.status(500).json({ message: "Internal Server Error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://172.17.150.164:${PORT}`));

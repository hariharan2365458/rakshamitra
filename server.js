// === Import dependencies ===
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const PORT = 3000;

// === Security Middlewares ===
app.use(helmet()); // adds security headers

// Limit repeated requests (prevents brute force attacks)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// === Parse incoming data ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// === Serve frontend files ===
app.use(express.static(path.join(__dirname, ".")));

// === Link safety check (simple demo version) ===
app.post("/check", (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ safe: false, reason: "No URL provided" });

  const unsafePatterns = [
    /\.ru\b/, /\.xyz\b/, /\.zip\b/, /\.mov\b/, /(free|bonus|gift|claim)/i,
    /(login|verify|update)[^a-z]*\d/i, /(tinyurl|bit\.ly|shorturl)/i
  ];

  const isUnsafe = unsafePatterns.some((pattern) => pattern.test(url));

  if (isUnsafe) {
    console.log(`[⚠️ ALERT] Suspicious link detected: ${url}`);
    return res.json({ safe: false, reason: "Suspicious domain or pattern" });
  }

  if (!/^https:\/\//.test(url)) {
    return res.json({ safe: false, reason: "Link is not using HTTPS" });
  }

  res.json({ safe: true, reason: "No suspicious patterns found" });
});

// === Email alert (optional setup) ===
async function sendSecurityAlert(email, message) {
  try {
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "yourgmail@gmail.com",
        pass: "your-app-password", // not your normal password
      },
    });

    await transporter.sendMail({
      from: '"RakshaMitra Security" <yourgmail@gmail.com>',
      to: email,
      subject: "Suspicious Activity Detected",
      text: message,
    });

    console.log("✅ Alert email sent successfully");
  } catch (error) {
    console.error("❌ Email sending failed:", error);
  }
}

// === Start Server ===
app.listen(PORT, () => {
  console.log(`🚀 RakshaMitra backend running at http://localhost:${PORT}`);
});

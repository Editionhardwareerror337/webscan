import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const API_KEY = process.env.VT_API_KEY;

const headers = {
  "x-apikey": API_KEY,
  "Content-Type": "application/x-www-form-urlencoded"
};

app.post("/scan", async (req, res) => {
  try {
    const { url } = req.body;

    const response = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers,
        body: `url=${encodeURIComponent(url)}`
      }
    );

    const data = await response.json();

    res.json(data);

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.get("/analysis/:id", async (req, res) => {
  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${req.params.id}`,
      {
        headers: {
          "x-apikey": API_KEY
        }
      }
    );

    const data = await response.json();

    res.json(data);

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
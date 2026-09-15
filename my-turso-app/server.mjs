import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("."));

const TURSO_URL = "https://nuru-nuruspage.aws-us-east-1.turso.io/v2/pipeline";
const TURSO_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODk0MzYyMzMsImlkIjoiMDFhMGEyOWEtNzkwMS03NzgzLThlNzctZTA2OWMzOWNiNGY0Iiwia2lkIjoici1OdTgtQVplX2d3T092SFo1T1ljd2FMMDlZR0dPdDlYMlpCczMtRTVjVSIsInJpZCI6IjQwMmY5MjJiLTI0OTktNDZlMi1hNGNhLTYyN2JhYjdjNjA4MCJ9.cjzLTLDWNVdaZBwVx4MdDVcP9xWB_SUFBGVqg0oVvd93hQzBeQxRaX84TfxUfh8YsZETPlMgeQnK0XIGCkiiBw";

// ከTurso ጋር የሚነጋገር አጠቃላይ ተግባር (Helper function)
async function executeQuery(sql, args = []) {
  const response = await fetch(TURSO_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${TURSO_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      requests: [
        { type: "execute", stmt: { sql, args } },
        { type: "close" }
      ]
    })
  });
  return await response.json();
}

// 1. የሰንጠረዥ/Table መኖርን ማረጋገጥ (የሌለ ከሆነ ይፈጥረዋል)
async function initDb() {
  const createTableSql = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL
    );
  `;
  await executeQuery(createTableSql);
}
initDb().catch(console.error);

// 2. መረጃዎችን ለማየት (GET request)
app.get("/api/users", async (req, res) => {
  try {
    const data = await executeQuery("SELECT * FROM users;");
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. አዲስ መረጃ ለመጨመር (POST request)
app.post("/api/users", async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: "ስም እና ኢሜይል ያስፈልጋል!" });
    }

    const sql = "INSERT INTO users (name, email) VALUES (?, ?);";
    const args = [
      { type: "text", value: name },
      { type: "text", value: email }
    ];

    const data = await executeQuery(sql, args);
    res.json({ message: "ተጠቃሚው በስኬት ተመዝግቧል!", result: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log("ሰርቨሩ በ http://localhost:3000 ላይ እየሰራ ነው");
});

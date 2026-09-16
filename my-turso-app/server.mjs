import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Static ፋይሎችን ማስተናገድ
app.use(express.static(__dirname));

// ኤፒአይዎች እና ሌሎች ጥያቄዎች እዚህ ይገባሉ...

// ለማንኛውም ሌላ ጥያቄ index.html ን መመለስ
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

export default app;

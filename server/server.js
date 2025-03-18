import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg

dotenv.config();

const app = express();
const PORT = 5009;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.use(cors());
app.use(express.json());

// Регистрация пользователя
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
      [username, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Вход пользователя
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Пользователь не найден' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Неверный пароль' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware для проверки JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Токен отсутствует' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Недействительный токен' });
    }
    req.user = user;
    next();
  });
}

// Получение задач пользователя
app.get('/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1', [req.user.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Создание задачи
app.post('/tasks', authenticateToken, async (req, res) => {
  const { title, description } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO tasks (title, description, user_id) VALUES ($1, $2, $3) RETURNING *',
      [title, description, req.user.userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});
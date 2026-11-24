const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();
// Путь к БД можно переопределить (в тестах используется ":memory:")
const db = new Database(process.env.DB_FILE || path.join(__dirname, "users.db"));
const PORT = process.env.PORT || 3000;

// Блокировка входа после нескольких неудачных попыток
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 5;

// Создание таблицы пользователей
// (индивидуальные задания: фамилия, роль, дата последнего входа, счётчик неудачных попыток)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    surname TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER
  )
`);

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Настройка сессий
app.use(session({
  name: "lab9.sid",
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // Для локальной работы по HTTP
    maxAge: 30 * 60 * 1000
  }
}));

// ---------- Вспомогательные функции проверки данных ----------

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateName(value, label) {
  if (typeof value !== "string") return `${label}: некорректное значение`;
  const clean = value.trim();
  if (clean.length < 2 || clean.length > 60) {
    return `${label} должно содержать от 2 до 60 символов`;
  }
  return null;
}

function validateEmail(value) {
  if (typeof value !== "string") return "Введите корректный email";
  const clean = value.trim().toLowerCase();
  if (clean.length > 254 || !EMAIL_RE.test(clean)) return "Введите корректный email";
  return null;
}

// Проверка сложности пароля: длина, наличие букв и цифр
function validatePassword(password) {
  if (typeof password !== "string") return "Введите пароль";
  if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
    return "Пароль должен содержать от 8 символов и не более 72 байт";
  }
  if (!/\p{L}/u.test(password) || !/\d/.test(password)) {
    return "Пароль должен содержать хотя бы одну букву и одну цифру";
  }
  return null;
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    surname: user.surname,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
    last_login: user.last_login
  };
}

function getUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

// ---------- Middleware ----------

// Проверка авторизации
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Необходимо войти в систему" });
  }
  const user = getUserById(req.session.userId);
  if (!user) {
    return res.status(401).json({ error: "Пользователь не найден" });
  }
  req.user = user;
  next();
}

// Проверка роли администратора (роль берётся из БД, а не из сессии)
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Доступ разрешён только администратору" });
    }
    next();
  });
}

// ---------- Маршруты ----------

// Регистрация
app.post("/api/register", (req, res) => {
  const { name, surname, email, password, confirmPassword } = req.body;

  const error =
    validateName(name, "Имя") ||
    validateName(surname, "Фамилия") ||
    validateEmail(email) ||
    validatePassword(password);
  if (error) return res.status(400).json({ error });

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Пароли не совпадают" });
  }

  const passwordHash = bcrypt.hashSync(password, 12);

  // Первый зарегистрированный пользователь становится администратором
  const usersCount = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
  const role = usersCount === 0 ? "admin" : "user";

  try {
    const result = db.prepare(`
      INSERT INTO users (name, surname, email, password_hash, role)
      VALUES (?, ?, ?, ?, ?)
    `).run(name.trim(), surname.trim(), email.trim().toLowerCase(), passwordHash, role);

    res.status(201).json({
      message: "Регистрация прошла успешно",
      userId: result.lastInsertRowid,
      role
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Пользователь с таким email уже существует" });
    }
    console.error(err);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Вход в систему
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Введите email и пароль" });
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?")
    .get(email.trim().toLowerCase());

  // Дополнительное задание: временная блокировка
  if (user && user.locked_until && user.locked_until > Date.now()) {
    const minutes = Math.ceil((user.locked_until - Date.now()) / 60000);
    return res.status(429).json({
      error: `Слишком много неудачных попыток. Повторите через ${minutes} мин.`
    });
  }

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    if (user) {
      const attempts = user.failed_attempts + 1;
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        db.prepare("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?")
          .run(Date.now() + LOCK_MINUTES * 60 * 1000, user.id);
        return res.status(429).json({
          error: `Слишком много неудачных попыток. Вход заблокирован на ${LOCK_MINUTES} мин.`
        });
      }
      db.prepare("UPDATE users SET failed_attempts = ? WHERE id = ?").run(attempts, user.id);
    }
    return res.status(401).json({ error: "Неверный email или пароль" });
  }

  // Успешный вход: сброс счётчика и фиксация времени последнего входа
  const previousLogin = user.last_login;
  db.prepare(`
    UPDATE users
    SET failed_attempts = 0, locked_until = NULL, last_login = datetime('now')
    WHERE id = ?
  `).run(user.id);

  // Защита от фиксации сессии
  req.session.regenerate((error) => {
    if (error) return res.status(500).json({ error: "Не удалось создать сессию" });

    req.session.userId = user.id;

    req.session.save((saveError) => {
      if (saveError) return res.status(500).json({ error: "Не удалось сохранить сессию" });

      res.json({
        message: "Вход выполнен успешно",
        previousLogin,
        user: publicUser(getUserById(user.id))
      });
    });
  });
});

// Получение данных текущего пользователя
app.get("/api/me", requireAuth, (req, res) => {
  res.json(publicUser(req.user));
});

// Редактирование собственного профиля
app.put("/api/me", requireAuth, (req, res) => {
  const { name, surname, email } = req.body;

  const error =
    validateName(name, "Имя") ||
    validateName(surname, "Фамилия") ||
    validateEmail(email);
  if (error) return res.status(400).json({ error });

  try {
    db.prepare("UPDATE users SET name = ?, surname = ?, email = ? WHERE id = ?")
      .run(name.trim(), surname.trim(), email.trim().toLowerCase(), req.user.id);
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Этот email уже занят" });
    }
    throw err;
  }

  res.json({ message: "Профиль обновлён", user: publicUser(getUserById(req.user.id)) });
});

// Смена пароля с проверкой старого пароля
app.put("/api/me/password", requireAuth, (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (typeof oldPassword !== "string" ||
      !bcrypt.compareSync(oldPassword, req.user.password_hash)) {
    return res.status(400).json({ error: "Старый пароль указан неверно" });
  }

  const error = validatePassword(newPassword);
  if (error) return res.status(400).json({ error });

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: "Новые пароли не совпадают" });
  }
  if (newPassword === oldPassword) {
    return res.status(400).json({ error: "Новый пароль должен отличаться от старого" });
  }

  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .run(bcrypt.hashSync(newPassword, 12), req.user.id);

  res.json({ message: "Пароль успешно изменён" });
});

// Маршруты администратора
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, name, surname, email, role, created_at, last_login
    FROM users ORDER BY id
  `).all();
  res.json(users);
});

app.put("/api/admin/users/:id/role", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { role } = req.body;

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Некорректный ID" });
  }
  if (role !== "user" && role !== "admin") {
    return res.status(400).json({ error: "Роль должна быть user или admin" });
  }
  if (id === req.user.id) {
    return res.status(400).json({ error: "Нельзя изменить собственную роль" });
  }

  const result = db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }
  res.json({ message: "Роль изменена" });
});

// Выход из системы
app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie("lab9.sid", { httpOnly: true, sameSite: "lax", secure: false });
    res.json({ message: "Вы вышли из системы" });
  });
});

// Обработка неожиданных ошибок
app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "Внутренняя ошибка сервера" });
});

// Запуск сервера только при прямом вызове `node server.js`;
// при подключении из тестов приложение просто экспортируется
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
  });
}

module.exports = app;

// Автоматические тесты Web-приложения (встроенный тест-раннер Node.js)
process.env.DB_FILE = ":memory:"; // тесты работают с временной БД в памяти

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const app = require("./server");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0); // случайный свободный порт
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://localhost:${server.address().port}`;
});

after(() => server.close());

// Простой HTTP-клиент, который запоминает cookie сессии
function createClient() {
  let cookie = "";
  return async function request(method, url, body) {
    const response = await fetch(baseUrl + url, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(cookie ? { Cookie: cookie } : {})
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) cookie = setCookie.split(";")[0];
    return { status: response.status, data: await response.json() };
  };
}

const admin = {
  name: "Алия", surname: "Ахметова", email: "aliya@example.com",
  password: "Test12345", confirmPassword: "Test12345"
};
const user = {
  name: "Бекзат", surname: "Серикулы", email: "bek@example.com",
  password: "Pass12345", confirmPassword: "Pass12345"
};

test("главная страница отдаётся сервером", async () => {
  const response = await fetch(baseUrl + "/");
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Управление пользователями/);
});

test("первый пользователь регистрируется с ролью admin", async () => {
  const { status, data } = await createClient()("POST", "/api/register", admin);
  assert.equal(status, 201);
  assert.equal(data.role, "admin");
});

test("второй пользователь получает роль user", async () => {
  const { status, data } = await createClient()("POST", "/api/register", user);
  assert.equal(status, 201);
  assert.equal(data.role, "user");
});

test("повторная регистрация с тем же email возвращает 409", async () => {
  const { status } = await createClient()("POST", "/api/register", admin);
  assert.equal(status, 409);
});

test("пароль без цифр отклоняется", async () => {
  const { status, data } = await createClient()("POST", "/api/register", {
    ...user, email: "weak@example.com", password: "onlyletters", confirmPassword: "onlyletters"
  });
  assert.equal(status, 400);
  assert.match(data.error, /букву и одну цифру/);
});

test("несовпадающие пароли отклоняются", async () => {
  const { status, data } = await createClient()("POST", "/api/register", {
    ...user, email: "other@example.com", confirmPassword: "Other12345"
  });
  assert.equal(status, 400);
  assert.equal(data.error, "Пароли не совпадают");
});

test("без входа /api/me возвращает 401", async () => {
  const { status } = await createClient()("GET", "/api/me");
  assert.equal(status, 401);
});

test("неверный пароль возвращает 401", async () => {
  const { status } = await createClient()("POST", "/api/login", {
    email: admin.email, password: "Wrong12345"
  });
  assert.equal(status, 401);
});

test("вход, профиль и выход", async () => {
  const request = createClient();

  const login = await request("POST", "/api/login", {
    email: admin.email, password: admin.password
  });
  assert.equal(login.status, 200);
  assert.equal(login.data.user.email, admin.email);

  const me = await request("GET", "/api/me");
  assert.equal(me.status, 200);
  assert.equal(me.data.surname, "Ахметова");
  assert.ok(me.data.last_login, "время последнего входа сохранено");
  assert.equal(me.data.password_hash, undefined, "хеш пароля не отдаётся клиенту");

  const logout = await request("POST", "/api/logout", {});
  assert.equal(logout.status, 200);

  const afterLogout = await request("GET", "/api/me");
  assert.equal(afterLogout.status, 401);
});

test("администратор видит список пользователей, обычный пользователь — нет", async () => {
  const adminClient = createClient();
  await adminClient("POST", "/api/login", { email: admin.email, password: admin.password });
  const list = await adminClient("GET", "/api/admin/users");
  assert.equal(list.status, 200);
  assert.equal(list.data.length, 2);

  const userClient = createClient();
  await userClient("POST", "/api/login", { email: user.email, password: user.password });
  const forbidden = await userClient("GET", "/api/admin/users");
  assert.equal(forbidden.status, 403);
});

test("смена пароля требует верный старый пароль", async () => {
  const request = createClient();
  await request("POST", "/api/login", { email: user.email, password: user.password });

  const wrong = await request("PUT", "/api/me/password", {
    oldPassword: "Bad12345", newPassword: "Fresh12345", confirmPassword: "Fresh12345"
  });
  assert.equal(wrong.status, 400);

  const ok = await request("PUT", "/api/me/password", {
    oldPassword: user.password, newPassword: "Fresh12345", confirmPassword: "Fresh12345"
  });
  assert.equal(ok.status, 200);
  user.password = "Fresh12345";
});

test("после 5 неудачных попыток вход блокируется (429)", async () => {
  const request = createClient();
  let last;
  for (let i = 0; i < 5; i++) {
    last = await request("POST", "/api/login", { email: user.email, password: "Wrong" + i });
  }
  assert.equal(last.status, 429);

  // даже верный пароль не принимается во время блокировки
  const blocked = await request("POST", "/api/login", { email: user.email, password: user.password });
  assert.equal(blocked.status, 429);
});

test("пользователь может изменить свой профиль", async () => {
  const request = createClient();
  await request("POST", "/api/login", { email: admin.email, password: admin.password });

  const updated = await request("PUT", "/api/me", {
    name: "Алия", surname: "Касымова", email: admin.email
  });
  assert.equal(updated.status, 200);
  assert.equal(updated.data.user.surname, "Касымова");

  const taken = await request("PUT", "/api/me", {
    name: "Алия", surname: "Касымова", email: user.email
  });
  assert.equal(taken.status, 409, "чужой email занять нельзя");
});

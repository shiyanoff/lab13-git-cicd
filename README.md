# lab13-git-cicd

[![CI](https://github.com/shiyanoff/lab13-git-cicd/actions/workflows/ci.yml/badge.svg)](https://github.com/shiyanoff/lab13-git-cicd/actions/workflows/ci.yml)

Учебное Web-приложение «Управление пользователями» на Node.js, Express и SQLite
с автоматическими тестами и непрерывной интеграцией (CI) на GitHub Actions.

Дисциплина: Промышленное Web-программирование. Модульное задание 4.

## Возможности

- регистрация с проверкой сложности и подтверждением пароля;
- вход и выход (сессии `express-session`, пароли хешируются `bcryptjs`);
- личный кабинет: редактирование профиля и смена пароля;
- роли `user` и `admin`, панель администратора;
- блокировка входа на 5 минут после 5 неудачных попыток.

## Требования

- Node.js 20 или новее
- npm

## Установка и запуск

```bash
git clone https://github.com/shiyanoff/lab13-git-cicd.git
cd lab13-git-cicd
npm install
npm start
```

Приложение откроется по адресу http://localhost:3000.

## Запуск тестов

```bash
npm test
```

Тесты используют встроенный тест-раннер Node.js (`node --test`) и временную
базу данных в памяти, поэтому рабочая база `users.db` не изменяется.

## CI

Файл `.github/workflows/ci.yml` запускает установку зависимостей (`npm ci`)
и тесты (`npm test`) при каждом `push` и `pull_request`.
Результаты видны на вкладке **Actions** репозитория.

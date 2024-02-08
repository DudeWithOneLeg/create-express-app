# CEA (Create Express App)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm version](https://badge.fury.io/js/cea.svg)](https://badge.fury.io/js/cea)

## Overview

The **CEA (Create Express App)** npm package simplifies the setup of a full-stack web application with user authentication. It provides a template [Express.js](https://expressjs.com/) backend and a [React](https://reactjs.org/) frontend, complete with essential middleware for security, authentication, and database interactions. The package aims to streamline the development process, allowing developers to focus on building features rather than dealing with boilerplate code and configuration.

## Features

- [Express.js](https://expressjs.com/) backend with security middleware ([CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS), [CSRF protection](https://owasp.org/www-community/attacks/csrf), [helmet](https://helmetjs.github.io/))
- User authentication with [JSON Web Tokens (JWT)](https://jwt.io/) and [bcrypt](https://github.com/kelektiv/node.bcrypt.js) for password hashing
- [React](https://reactjs.org/) frontend with [Redux](https://redux.js.org/) for state management
- [Sequelize](https://sequelize.org/) ORM for database interactions (SQLite for development, PostgreSQL for production)
- Convenient scripts for [migrating](#database-migration-and-seeding) and [seeding](#database-migration-and-seeding) databases

## Installation

1. To reate an [Express](https://expressjs.com/) app, run this command in your project's root folder:

   npx create-e.x.p.r.re.s.s-app

2. Navigate to the /backend directory and start the server:

   cd backend && npm start

3. Navigate to the /frontend directory and start the [React](https://reactjs.org/) app:

   cd frontend && npm start

4. To make changes to the migrations you must [unseed](#unseed-database) and [unapply migrations](#unmigrate-database)

## Configuration

### Environment Variables

Environment variables are already included in /backend:

```env
PORT=8000
DB_FILE=db/dev.db
JWT_SECRET=«generate_strong_secret_here»
JWT_EXPIRES_IN=604800
SCHEMA=«custom_schema_name_here»
```

## Database Migration and Seeding

### Migrate Database:

Run the following command to perform [migrations](#migrate-database):

```bash
npx dotenv sequelize db:migrate
```

### Seed Database:

Run the following command to [seed](#seed-database) the database:

```bash
npx dotenv sequelize db:seed:all
```

### Unseed Database:

To [unseed](#unseed-database) the database, run:

```bash
npx dotenv sequelize db:seed:undo:all
```

### Unmigrate Database:

To [unapply migrations](#unmigrate-database), run:

```bash
npx dotenv sequelize db:migrate:undo:all
```

### Reapply Migrations and Seeds:

To make changes to [migrations](#reapply-migrations-and-seeds), first, [unseed](#unseed-database) and [unapply migrations](#unmigrate-database), then reapply and reseed:

```bash
npx dotenv sequelize db:seed:undo:all
npx dotenv sequelize db:migrate:undo:all
npx dotenv sequelize db:migrate
npx dotenv sequelize db:seed:all
```

## Deploying to Render:

1. Create a PostgreSQL Database, name it and choose your region. Copy the Internal DB URL.

2. Start a new Web Service

3. Choose your Github repo

4. Name your web service and choose your region.

5. Build command
   ```bash
   npm install && npm run render-postbuild && npm run build && npm run sequelize --prefix backend db:migrate && npm run sequelize --prefix backend db:seed:all
   ```

6. Add Environment variables
   ```bash
   PORT=8000
   DB_FILE=db/dev.db
   JWT_SECRET=(click 'Generate')
   JWT_EXPIRES_IN=604800
   SCHEMA=«custom_schema_name_here»
   NODE_ENV=production
   ```

7. Create Web Service

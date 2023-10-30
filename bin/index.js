#! /usr/bin/env node
const args = process.argv.slice(2);
const dir = args.length ? args[0].split('/').join('/') + ("/" + args[1] || "/exprss-app/") : ""

const fs = require("fs");
const util = require("util");
const exec = util.promisify(require("child_process").exec);

// Specify the directory where you want to run the command
const directoryPath = "backend";
console.log((dir + "/" || "/") + "backend")

// The command you want to execute
const command =
  "npm init -y && npm install cookie-parser cors csurf dotenv express express-async-errors helmet jsonwebtoken morgan per-env sequelize@6 sequelize-cli@6 pg bcryptjs express-validator && npm install -D sqlite3 dotenv-cli nodemon";

// Options for the child process
const options = {
  cwd: directoryPath, // Set the current working directory
};
// Execute the command in the specified directory

fs.writeFile(
  ".gitignore",
  `
node_modules
.env
build
.DS_Store
*.db`,
  function (err) {
    if (err) throw err;
    console.log("Gitignore created successfully");
    console.log('Installing dependencies...')
  }
);

fs.mkdir("frontend", (err) => {
  if (err) {
    return console.error(err);
  }
  console.log("Frontend folder created successfully!");
});

fs.mkdir("backend", (err) => {
  if (err) {
    return console.error(err);
  }
  console.log("Backend folder created successfully!");
});

const runCommand = (command, options, callback) => {
  if (command) {

    return exec(command, options, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return callback(error);
      }
      console.log(stdout ? stdout : "");
      console.log(stderr ? stderr : "");

      callback(null);
    });
  }
  return
};

// Run `sequelize init` command
runCommand(command, options, (error) => {
  if (error) {
    console.error("Failed to run sequelize init command.");
    return;
  }
  fs.writeFile(
    "backend/.env",
    `
PORT=8000
DB_FILE=db/dev.db
JWT_SECRET=«generate_strong_secret_here»
JWT_EXPIRES_IN=604800
SCHEMA=«custom_schema_name_here»`,
    function (err) {
      if (err) throw err;
      console.log("Saved!");
    }
  );

  fs.mkdir("backend/config", (err) => {
    if (err) {
      return console.error(err);
    }
    console.log("Config folder created successfully!");
  });
  exec("cd ../", options, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log(stdout ? stdout : "");
    console.log(stderr ? stderr : "");
  });

  fs.appendFile(
    "backend/config/index.js",
    `
module.exports = {
  environment: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 8000,
  dbFile: process.env.DB_FILE,
  jwtConfig: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN
  }
};`,
    function (err) {
      if (err) throw err;
      console.log("Saved!");
    }
  );

  fs.writeFile(
    "backend/.sequelizerc",
    `
const path = require('path');

module.exports = {
  config: path.resolve('config', 'database.js'),
  'models-path': path.resolve('db', 'models'),
  'seeders-path': path.resolve('db', 'seeders'),
  'migrations-path': path.resolve('db', 'migrations')
};`,
    function (err) {
      if (err) throw err;
      console.log("Sequelizerc created...");
    }
  );

  fs.writeFile(
    "backend/package.json",
    `
{
  "name": "backend",
  "version": "1.0.0",
  "main": "app.js",
  "scripts": {
    "sequelize": "sequelize",
    "sequelize-cli": "sequelize-cli",
    "start": "per-env",
    "start:development": "nodemon ./bin/www",
    "start:production": "node ./bin/www",
    "build": "node psql-setup-script.js"

  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "ansi-regex": "^5.0.1",
    "accepts": "^1.3.8",
    "ansi-styles": "^4.3.0",
    "abbrev": "^1.1.1",
    "array-flatten": "^1.1.1",
    "at-least-node": "^1.0.0",
    "balanced-match": "^1.0.2",
    "bluebird": "^3.7.2",
    "basic-auth": "^2.0.1",
    "brace-expansion": "^2.0.1",
    "buffer-equal-constant-time": "^1.0.1",
    "buffer-writer": "^2.0.0",
    "color-convert": "^2.0.1",
    "color-name": "^1.1.4",
    "config-chain": "^1.1.13",
    "content-disposition": "^0.5.4",
    "bytes": "^3.1.2",
    "content-type": "^1.0.5",
    "cookie": "^0.4.1",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "cookie-signature": "^1.0.6",
    "csrf": "^3.1.0",
    "csurf": "^1.11.0",
    "d": "^1.0.1",
    "debug": "^2.6.9",
    "depd": "^2.0.0",
    "destroy": "^1.2.0",
    "dottie": "^2.0.6",
    "ecdsa-sig-formatter": "^1.0.11",
    "ee-first": "^1.1.1",
    "emoji-regex": "^8.0.0",
    "encodeurl": "^1.0.2",
    "es6-iterator": "^2.0.3",
    "es6-weak-map": "^2.0.3",
    "escalade": "^3.1.1",
    "etag": "^1.8.1",
    "escape-html": "^1.0.3",
    "event-emitter": "^0.3.5",
    "finalhandler": "^1.2.0",
    "forwarded": "^0.2.0",
    "fresh": "^0.5.2",
    "fs.realpath": "^1.0.0",
    "get-caller-file": "^2.0.5",
    "graceful-fs": "^4.2.11",
    "has-proto": "^1.0.1",
    "has": "^1.0.4",
    "helmet": "^7.0.0",
    "express-async-errors": "^3.1.1",
    "http-errors": "^1.7.3",
    "inflection": "^1.13.4",
    "iconv-lite": "^0.4.24",
    "inherits": "^2.0.4",
    "ini": "^1.3.8",
    "inflight": "^1.0.6",
    "ipaddr.js": "^1.9.1",
    "is-fullwidth-code-point": "^3.0.0",
    "is-promise": "^2.2.2",
    "jsonfile": "^6.1.0",
    "jwa": "^1.4.1",
    "jws": "^3.2.2",
    "lodash.includes": "^4.3.0",
    "lodash.isinteger": "^4.0.4",
    "lodash.isboolean": "^3.0.3",
    "lodash.isplainobject": "^4.0.6",
    "lodash.isstring": "^4.0.1",
    "lodash.once": "^4.1.1",
    "lodash.isnumber": "^3.0.3",
    "lru-queue": "^0.1.0",
    "lru-cache": "^6.0.0",
    "media-typer": "^0.3.0",
    "merge-descriptors": "^1.0.1",
    "methods": "^1.1.2",
    "mime": "^1.6.0",
    "morgan": "^1.10.0",
    "ms": "^2.0.0",
    "object-assign": "^4.1.1",
    "on-finished": "^2.4.1",
    "packet-reader": "^1.0.0",
    "parseurl": "^1.3.3",
    "once": "^1.4.0",
    "path-parse": "^1.0.7",
    "per-env": "^1.0.2",
    "on-headers": "^1.0.2",
    "path-to-regexp": "^0.1.7",
    "pg-cloudflare": "^1.1.1",
    "pg-int8": "^1.0.1",
    "pg-connection-string": "^2.6.2",
    "pg-types": "^2.2.0",
    "pgpass": "^1.0.5",
    "postgres-bytea": "^1.0.0",
    "postgres-array": "^2.0.0",
    "postgres-date": "^1.0.7",
    "postgres-interval": "^1.2.0",
    "proto-list": "^1.2.4",
    "proxy-addr": "^2.0.7",
    "random-bytes": "^1.0.0",
    "mime-types": "^2.1.35",
    "range-parser": "^1.2.1",
    "require-directory": "^2.1.1",
    "safe-buffer": "^5.2.1",
    "safer-buffer": "^2.1.2",
    "send": "^0.18.0",
    "rndm": "^1.2.0",
    "raw-body": "^2.5.1",
    "serve-static": "^1.15.0",
    "setprototypeof": "^1.2.0",
    "split2": "^4.2.0",
    "statuses": "^2.0.1",
    "string-width": "^4.2.3",
    "strip-ansi": "^6.0.1",
    "timers-ext": "^0.1.7",
    "toidentifier": "^1.0.0",
    "toposort-class": "^1.0.1",
    "tsscmp": "^1.0.6",
    "type-is": "^1.6.18",
    "uid-safe": "^2.1.5",
    "undici-types": "^5.25.3",
    "universalify": "^2.0.0",
    "unpipe": "^1.0.0",
    "utils-merge": "^1.0.1",
    "vary": "^1.1.2",
    "wrap-ansi": "^7.0.0",
    "wrappy": "^1.0.2",
    "xtend": "^4.0.2",
    "yallist": "^4.0.0"
  },
  "devDependencies": {},
  "description": ""
}
  `,
    function (err) {
      if (err) throw err;
      console.log("Scripts added to package.json...");
    }
  );

  exec("pwd", options, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log(stdout ? "pwd" + stdout : "");
    console.log(stderr ? stderr : "");
  });

  // Once `sequelize init` is complete, run `sequelize db:migrate` command
  runCommand("npx sequelize init", options, (error) => {
    if (error) {
      console.error("Failed to run sequelize init command.");
      return;
    }
    fs.writeFile(
      "backend/config/database.js",
      `
const config = require('./index');

module.exports = {
  development: {
    storage: config.dbFile,
    dialect: "sqlite",
    seederStorage: "sequelize",
    logQueryParameters: true,
    typeValidation: true
  },
  production: {
    use_env_variable: 'DATABASE_URL',
    dialect: 'postgres',
    seederStorage: 'sequelize',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    },
    define: {
      schema: process.env.SCHEMA
    }
  }
};
      `,
      function (err) {
        if (err) throw err;
        console.log("Initiating Sequelize...");
      }
    );

    fs.writeFile(
      "backend/psql-setup-script.js",
      `
const { sequelize } = require('./db/models');

sequelize.showAllSchemas({ logging: false }).then(async (data) => {
  if (!data.includes(process.env.SCHEMA)) {
    await sequelize.createSchema(process.env.SCHEMA);
  }
});
`,
      function (err) {
        if (err) throw err;
        console.log("Writing Psql script...");
      }
    );

    runCommand("npx dotenv sequelize db:migrate", options, (error) => {
      if (error) {
        console.error("Failed to run sequelize db:migrate command.");
        return;
      }
    });
    fs.writeFile(
      "backend/app.js",
      `
const express = require('express');
require('express-async-errors');
const morgan = require('morgan');
const cors = require('cors');
const csurf = require('csurf');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const routes = require('./routes');
const { ValidationError } = require('sequelize');

const { environment } = require('./config');
const isProduction = environment === 'production';

const app = express();
app.use(cookieParser());

// Set the _csrf token and create req.csrfToken method
app.use(
  csurf({
    cookie: {
      secure: isProduction,
      sameSite: isProduction && "Lax",
      httpOnly: true
    }
  })
);

app.use(morgan('dev'));
app.use(express.json());

// Security Middleware
if (!isProduction) {
  // enable cors only in development
  app.use(cors());
}

// helmet helps set a variety of headers to better secure your app
app.use(
  helmet.crossOriginResourcePolicy({
    policy: "cross-origin"
  })
);

app.use(routes);

app.use((_req, _res, next) => {
  const err = new Error("The requested resource couldn't be found.");
  err.title = "Resource Not Found";
  err.errors = { message: "The requested resource couldn't be found." };
  err.status = 404;
  next(err);
});

app.use((err, _req, _res, next) => {
  // check if error is a Sequelize error:
  if (err instanceof ValidationError) {
    let errors = {};
    for (let error of err.errors) {
      errors[error.path] = error.message;
    }
    err.title = 'Validation error';
    err.errors = errors;
  }
  next(err);
});

app.use((err, _req, res, _next) => {
  res.status(err.status || 500);
  console.error(err);
  res.json({
    title: err.title || 'Server Error',
    message: err.message,
    errors: err.errors,
    stack: isProduction ? null : err.stack
  });
});

module.exports = app;
      `,
      function (err) {
        if (err) throw err;
        console.log('Dev db migrated...')
        console.log("Writing app...");
      }
    );

    fs.mkdir("backend/routes", (err) => {
      if (err) {
        return console.error(err);
      }
      console.log("Backend routes folder...");
    });

    exec("pwd", options, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return;
      }
      console.log(stdout ? "pwd" + stdout : "");
    console.log(stderr ? stderr : "");
    });

    fs.writeFile(
      "backend/routes/index.js",
      `
const express = require('express')
const router = express.Router()
const apiRouter = require('./api');

router.use('/api', apiRouter);

if (process.env.NODE_ENV === 'production') {
  const path = require('path');
  // Serve the frontend's index.html file at the root route
  router.get('/', (req, res) => {
    res.cookie('XSRF-TOKEN', req.csrfToken());
    return res.sendFile(
      path.resolve(__dirname, '../../frontend', 'build', 'index.html')
    );
  });

  // Serve the static assets in the frontend's build folder
  router.use(express.static(path.resolve("../frontend/build")));

  // Serve the frontend's index.html file at all other routes NOT starting with /api
  router.get(/^(?!\\/?api).*/, (req, res) => {
    res.cookie('XSRF-TOKEN', req.csrfToken());
    return res.sendFile(
      path.resolve(__dirname, '../../frontend', 'build', 'index.html')
    );
  });
}

if (process.env.NODE_ENV !== 'production') {
  router.get('/api/csrf/restore', (req, res) => {
    res.cookie('XSRF-TOKEN', req.csrfToken());
    return res.json({});
  });
}

module.exports = router;`,
      function (err) {
        if (err) throw err;
        console.log("Writing backend routes index...");
      }
    );

    fs.mkdir("backend/bin", (err) => {
      if (err) {
        return console.error(err);
      }
      console.log("Bin folder created successfully!");
    });
    exec("pwd", options, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return;
      }
      console.log(stdout ? stdout : "");
    console.log(stderr ? stderr : "");
    });

    fs.writeFile(
      "backend/bin/www",
`#!/usr/bin/env node
// backend/bin/www

// Import environment variables
require('dotenv').config();

const { port } = require('../config');

const app = require('../app');
const db = require('../db/models');

// Check the database connection before starting the app
db.sequelize
  .authenticate()
  .then(() => {
    console.log('Database connection success! Sequelize is ready to use...');

    // Start listening for connections
    app.listen(port, () => console.log(\`Listening on port \${port}...\`));
  })
  .catch((err) => {
    console.log('Database connection failure.');
    console.error(err);
  });`,
      function (err) {
        if (err) throw err;
        console.log("Connecting db and server");
      }
    );

    console.log("sequelize db:migrate command completed successfully.");

    fs.mkdir("backend/routes/api", (err) => {
      if (err) {
        return console.error(err);
      }
      console.log("Api folder created successfully!");
    });
    exec("pwd", (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return;
      }
      console.log(stdout ? stdout : "");
    console.log(stderr ? stderr : "");
    });

    fs.writeFile(
      "backend/routes/api/index.js",
      `
const router = require('express').Router();
const sessionRouter = require('./session.js');
const usersRouter = require('./users.js');
const { setTokenCookie } = require('../../utils/auth.js');
const { User } = require('../../db/models');
const { restoreUser } = require('../../utils/auth.js');
const { requireAuth } = require('../../utils/auth.js');

router.use(restoreUser);

router.use('/session', sessionRouter);

router.use('/users', usersRouter);

router.get(
  '/restore-user',
  (req, res) => {
    return res.json(req.user);
  }
);

module.exports = router;
`,
      function (err) {
        if (err) throw err;
        console.log("Writing api route.");
      }
    );
    runCommand("npx sequelize model:generate --name User --attributes username:string,email:string,hashedPassword:string", options, (error) => {
      if (error) {
        console.error("Failed to generate Users model.");
        return;
      }
      const migrations = fs.readdirSync('./backend/db/migrations');
      fs.writeFile(
        `backend/db/migrations/${migrations[0]}`,
        `
"use strict";

/** @type {import('sequelize-cli').Migration} */
let options = {};
if (process.env.NODE_ENV === 'production') {
  options.schema = process.env.SCHEMA;  // define your schema in options object
}

module.exports = {
  up: async (queryInterface, Sequelize) => {
    return queryInterface.createTable("Users", {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      username: {
        type: Sequelize.STRING(30),
        allowNull: false,
        unique: true
      },
      email: {
        type: Sequelize.STRING(256),
        allowNull: false,
        unique: true
      },
      hashedPassword: {
        type: Sequelize.STRING.BINARY,
        allowNull: false
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
      }
    }, options);
  },
  down: async (queryInterface, Sequelize) => {
    options.tableName = "Users";
    return queryInterface.dropTable(options);
  }
};
  `,
        function (err) {
          if (err) throw err;
          console.log("Migrating Users Table...");
        }
      );
      fs.writeFile(
        `backend/db/models/user.js`,
        `
'use strict';
const { Model, Validator } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    static associate(models) {
      // define association here
    }
  };

  User.init(
    {
      username: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [4, 30],
          isNotEmail(value) {
            if (Validator.isEmail(value)) {
              throw new Error("Cannot be an email.");
            }
          }
        }
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [3, 256],
          isEmail: true
        }
      },
      hashedPassword: {
        type: DataTypes.STRING.BINARY,
        allowNull: false,
        validate: {
          len: [60, 60]
        }
      }
    }, {
      sequelize,
      modelName: 'User'
    }
  );
  return User;
};
  `,
        function (err) {
          if (err) throw err;
          console.log("Writing Users model");
        }
      );
      runCommand("npx dotenv sequelize db:migrate", options, (error) => {
        if (error) {
          console.error("Failed to migrate Users model.");
          return;
        }
        // runCommand("npx dotenv sequelize db:seed:all", options, (error) => {
        //   if (error) {
        //     console.error("Failed to generate Users model.");
        //     return;
        //   }
        // })
        fs.mkdir("backend/utils", (err) => {
          if (err) {
            return console.error(err);
          }
          console.log("Utils folder created successfully!");
          fs.writeFile(
            `backend/utils/auth.js`,
            `
  const jwt = require('jsonwebtoken');
  const { jwtConfig } = require('../config');
  const { User } = require('../db/models');

  const { secret, expiresIn } = jwtConfig;

  const setTokenCookie = (res, user) => {
    // Create the token.
    const safeUser = {
      id: user.id,
      email: user.email,
      username: user.username,
    };
    const token = jwt.sign(
      { data: safeUser },
      secret,
      { expiresIn: parseInt(expiresIn) } // 604,800 seconds = 1 week
    );

    const isProduction = process.env.NODE_ENV === "production";

    // Set the token cookie
    res.cookie('token', token, {
      maxAge: expiresIn * 1000, // maxAge in milliseconds
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction && "Lax"
    });

    return token;
  };

  const restoreUser = (req, res, next) => {
    // token parsed from cookies
    const { token } = req.cookies;
    req.user = null;

    return jwt.verify(token, secret, null, async (err, jwtPayload) => {
      if (err) {
        return next();
      }

      try {
        const { id } = jwtPayload.data;
        req.user = await User.findByPk(id, {
          attributes: {
            include: ['email', 'createdAt', 'updatedAt']
          }
        });
      } catch (e) {
        res.clearCookie('token');
        return next();
      }

      if (!req.user) res.clearCookie('token');

      return next();
    });
  };

  // If there is no current user, return an error
  const requireAuth = function (req, _res, next) {
    if (req.user) return next();

    const err = new Error('Authentication required');
    err.title = 'Authentication required';
    err.errors = { message: 'Authentication required' };
    err.status = 401;
    return next(err);
  };

  module.exports = { setTokenCookie, restoreUser, requireAuth };
      `,
            function (err) {
              if (err) throw err;
              console.log("Writing utils/auth...");
            }
          );
        });

        runCommand("npx sequelize seed:generate --name demo-user", options, (error) => {
          if (error) {
            console.error("Failed to generate Users model.");
            return;
          }
          const seeders = fs.readdirSync('./backend/db/seeders');
          fs.writeFile(
            `backend/db/seeders/${seeders[0]}`,
            `
'use strict';

const { query } = require('express');
const bcrypt = require('bcryptjs');

/** @type {import('sequelize-cli').Migration} */

let options = {};
if (process.env.NODE_ENV === 'production') {
  options.schema = process.env.SCHEMA; // define your schema in options object
}
options.tableName = 'Users'

module.exports = {
  async up(queryInterface, Sequelize) {
    /**
     * Add seed commands here.
     *
     * Example:
     * await queryInterface.bulkInsert('People', [{
     *   name: 'John Doe',
     *   isBetaMember: false
     * }], {});
    */
    const validUsers = [
      {
        email: 'demo@user.io',
        username: 'Demo-lition',
        hashedPassword: bcrypt.hashSync('password')
      },

    ]

   await queryInterface.bulkInsert(options, validUsers, {})
  },

  async down(queryInterface, Sequelize) {
    /**
     * Add commands to revert seed here.
     *
     * Example:
     * await queryInterface.bulkDelete('People', null, {});
     */
    await queryInterface.bulkDelete(options, {
      id: [1]
    }, {});
  }
};

      `,
            function (err) {
              if (err) throw err;
              console.log("Generated Users seeder...");
            }
          );
          runCommand("npx dotenv sequelize db:seed:all", options, (error) => {
            if (error) {
              console.error("Failed to seed Users model.");
              return;
            }
            fs.writeFile(
              "backend/routes/api/users.js",
              `
const express = require('express');
const bcrypt = require('bcryptjs');

const { setTokenCookie, requireAuth } = require('../../utils/auth');
const { User } = require('../../db/models');
const { check } = require('express-validator');
const { handleValidationErrors } = require('../../utils/validation');

const validateSignup = [
  check('email')
    .exists({ checkFalsy: true })
    .isEmail()
    .withMessage('Please provide a valid email.'),
  check('username')
    .exists({ checkFalsy: true })
    .isLength({ min: 4 })
    .withMessage('Please provide a username with at least 4 characters.'),
  check('username')
    .not()
    .isEmail()
    .withMessage('Username cannot be an email.'),
  check('password')
    .exists({ checkFalsy: true })
    .isLength({ min: 6 })
    .withMessage('Password must be 6 characters or more.'),
  handleValidationErrors
];

const router = express.Router();

// Restore session user
router.get(
  '/',
  (req, res) => {
    const { user } = req;
    if (user) {
      const safeUser = {
        id: user.id,
        email: user.email,
        username: user.username,
      };
      return res.json({
        user: safeUser
      });
    } else return res.json({ user: null });
  }
);

// Sign up
router.post(
  '/',
  validateSignup,
  async (req, res) => {
    const { email, password, username } = req.body;
    const hashedPassword = bcrypt.hashSync(password);
    const user = await User.create({ email, username, hashedPassword });

    const safeUser = {
      id: user.id,
      email: user.email,
      username: user.username,
    };

    await setTokenCookie(res, safeUser);

    return res.json({
      user: safeUser
    });
  }
);

module.exports = router;
        `,
              function (err) {
                if (err) throw err;
                console.log("Seeded Users table...");
              }
            );
            fs.writeFile(
              "backend/routes/api/session.js",
              `
const express = require('express');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');

const { check } = require('express-validator');
const { handleValidationErrors } = require('../../utils/validation');
const { setTokenCookie, restoreUser } = require('../../utils/auth');
const { User } = require('../../db/models');

const validateLogin = [
  check('credential')
    .exists({ checkFalsy: true })
    .notEmpty()
    .withMessage('Please provide a valid email or username.'),
  check('password')
    .exists({ checkFalsy: true })
    .withMessage('Please provide a password.'),
  handleValidationErrors
];

const router = express.Router();

router.get(
  '/',
  (req, res) => {
    const { user } = req;
    if (user) {
      const safeUser = {
        id: user.id,
        email: user.email,
        username: user.username,
      };
      return res.json({
        user: safeUser
      });
    } else return res.json({ user: null });
  }
);

router.post(
  '/',
  validateLogin,
  async (req, res, next) => {
    const { credential, password } = req.body;

    const user = await User.findOne({
      where: {
        [Op.or]: {
          username: credential,
          email: credential
        }
      }
    });

    if (!user || !bcrypt.compareSync(password, user.hashedPassword.toString())) {
      const err = new Error('Login failed');
      err.status = 401;
      err.title = 'Login failed';
      err.errors = { credential: 'The provided credentials were invalid.' };
      return next(err);
    }

    const safeUser = {
      id: user.id,
      email: user.email,
      username: user.username,
    };

    await setTokenCookie(res, safeUser);

    return res.json({
      user: safeUser
    });
  }
);

router.delete(
  '/',
  (_req, res) => {
    res.clearCookie('token');
    return res.json({ message: 'success' });
  }
);

module.exports = router;
        `,
              function (err) {
                if (err) throw err;
                console.log("Writing api/session...");
              }
            );
            fs.writeFile('backend/utils/validation.js',
            `
const { validationResult } = require('express-validator');

// middleware for formatting errors from express-validator middleware
// (to customize, see express-validator's documentation)
const handleValidationErrors = (req, _res, next) => {
  const validationErrors = validationResult(req);

  if (!validationErrors.isEmpty()) {
    const errors = {};
    validationErrors
      .array()
      .forEach(error => errors[error.param] = error.msg);

    const err = Error("Bad request.");
    err.errors = errors;
    err.status = 400;
    err.title = "Bad request.";
    next(err);
  }
  next();
};

module.exports = {
  handleValidationErrors
};
            `,
            function (err) {
              if (err) throw err;
              console.log("Writing db validations...");
            }
            )
            let dir
            exec("pwd", (error, stdout, stderr) => {
              if (error) {
                console.error(`Error: ${error}`);
                return;
              }
              dir = stdout.split('/')
              console.log(stdout ? stdout : "");
              console.log(stderr ? stderr : "");
              dir = dir[dir.length - 1].split('\n')[0]
              fs.writeFile('package.json',
              `
  {
    "name": "${dir}",
    "version": "1.0.0",
    "description": "",
    "main": "index.js",
    "scripts": {
      "render-postbuild": "npm run build --prefix frontend",
      "install": "npm --prefix backend install backend && npm --prefix frontend install frontend",
      "dev:backend": "npm install --prefix backend start",
      "dev:frontend": "npm install --prefix frontend start",
      "sequelize": "npm run --prefix backend sequelize",
      "sequelize-cli": "npm run --prefix backend sequelize-cli",
      "start": "npm start --prefix backend",
      "build": "npm run build --prefix backend"
    },
    "author": "",
    "license": "ISC"
  }
              `
              ,
              function (err) {
                if (err) throw err;
                console.log("Writing package.json in root");
                console.log('Creating React app. This might take a couple of minutes.')
              }
              )
              options.cwd = 'frontend'
              runCommand("npx create-react-app . --template @appacademy/react-redux-v17 --use-npm && npm install js-cookie", options, (error) => {
                if (error) {
                  console.error("Failed to create React app.");
                  return;
                }

                runCommand("pwd", (error) => {
                  if (error) {
                    console.error("Failed to create React app.");
                    return;

                  }

                  fs.mkdir("frontend/src/components", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("frontend/src/components folder created successfully!");

                  });


                  fs.writeFile('frontend/package.json',
                `
  {
    "name": "frontend",
    "version": "0.1.0",
    "private": true,
    "dependencies": {
      "@testing-library/jest-dom": "^5.17.0",
      "@testing-library/react": "^11.2.7",
      "@testing-library/user-event": "^12.8.3",
      "js-cookie": "^3.0.5",
      "react": "^18.2.0",
      "react-dom": "^18.2.0",
      "react-redux": "^7.2.9",
      "react-router-dom": "^5.3.4",
      "react-scripts": "5.0.1",
      "redux": "^4.2.1",
      "redux-thunk": "^2.4.2"
    },
    "scripts": {
      "start": "react-scripts start",
      "build": "react-scripts build",
      "test": "react-scripts test",
      "eject": "react-scripts eject"
    },
    "eslintConfig": {
      "extends": "react-app"
    },
    "browserslist": {
      "production": [
        ">0.2%",
        "not dead",
        "not op_mini all"
      ],
      "development": [
        "last 1 chrome version",
        "last 1 firefox version",
        "last 1 safari version"
      ]
    },
    "devDependencies": {
      "redux-logger": "^3.0.6"
    },
    "proxy": "http://localhost:8000"
  }
                `
                ,
                function (err) {
                  if (err) throw err;
                  console.log("Adding proxy to frontend package.json");
                })

                fs.writeFile('frontend/src/store/csrf.js',
                `
  import Cookies from 'js-cookie';

  export async function csrfFetch(url, options = {}) {
    // set options.method to 'GET' if there is no method
    options.method = options.method || 'GET';
    // set options.headers to an empty object if there is no headers
    options.headers = options.headers || {};

    // if the options.method is not 'GET', then set the "Content-Type" header to
      // "application/json", and set the "XSRF-TOKEN" header to the value of the
      // "XSRF-TOKEN" cookie
    if (options.method.toUpperCase() !== 'GET') {
      options.headers['Content-Type'] =
        options.headers['Content-Type'] || 'application/json';
      options.headers['XSRF-Token'] = Cookies.get('XSRF-TOKEN');
    }
    // call the default window's fetch with the url and the options passed in
    const res = await window.fetch(url, options);

    // if the response status code is 400 or above, then throw an error with the
      // error being the response
    if (res.status >= 400) throw res;

    // if the response status code is under 400, then return the response to the
      // next promise chain
    return res;
  }

  // call this to get the "XSRF-TOKEN" cookie, should only be used in development
  export function restoreCSRF() {
    return csrfFetch('/api/csrf/restore');
  }
                `
                ,
                function (err) {
                  if (err) throw err;
                  console.log("Writing frontend csrfFetch");
                })

                fs.writeFile('frontend/src/store/index.js',
                `
  import { createStore, combineReducers, applyMiddleware, compose } from "redux";
  import thunk from "redux-thunk";
  import sessionReducer from "./session";

  const rootReducer = combineReducers({
    session: sessionReducer,
  });

  let enhancer;

  if (process.env.NODE_ENV === "production") {
    enhancer = applyMiddleware(thunk);
  } else {
    const logger = require("redux-logger").default;
    const composeEnhancers =
      window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ || compose;
    enhancer = composeEnhancers(applyMiddleware(thunk, logger));
  }

  const configureStore = (preloadedState) => {
    return createStore(rootReducer, preloadedState, enhancer);
  };

  export default configureStore;
                `
                ,
                function (err) {
                  if (err) throw err;
                  console.log("Configuring Redux store.");
                })

                fs.writeFile('frontend/src/index.js',
                `
  import React from 'react';
  import ReactDOM from 'react-dom';
  import { BrowserRouter } from 'react-router-dom';
  import { Provider } from 'react-redux';
  import './index.css';
  import App from './App';
  import configureStore from './store';
  import { restoreCSRF, csrfFetch } from './store/csrf';
  import ModalProvider from './context/Modal.js'

  const store = configureStore();

  if (process.env.NODE_ENV !== 'production') {
    restoreCSRF();

    window.csrfFetch = csrfFetch;
    window.store = store;
  }

  function Root() {
    return (
      <ModalProvider>
        <Provider store={store}>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </Provider>
      </ModalProvider>
    );
  }

  ReactDOM.render(
    <React.StrictMode>
      <Root />
    </React.StrictMode>,
    document.getElementById('root')
  );
                `
                ,
                function (err) {
                  if (err) throw err;
                  console.log("Writing frontend index.");
                })

                fs.writeFile('frontend/src/store/session.js',
                `
  import { csrfFetch } from "./csrf";

  const SET_USER = "session/setUser";
  const REMOVE_USER = "session/removeUser";

  const setUser = (user) => {
    return {
      type: SET_USER,
      payload: user,
    };
  };

  const removeUser = () => {
    return {
      type: REMOVE_USER,
    };
  };

  export const login = (user) => async (dispatch) => {
    const { credential, password } = user;
    const response = await csrfFetch("/api/session", {
      method: "POST",
      body: JSON.stringify({
        credential,
        password,
      }),
    });
    const data = await response.json();
    dispatch(setUser(data.user));
    return response;
  };

  export const restoreUser = () => async (dispatch) => {
    const response = await csrfFetch("/api/session");
    const data = await response.json();
    dispatch(setUser(data.user));
    return response;
  };

  export const signup = (user) => async (dispatch) => {
    const { username, firstName, lastName, email, password } = user;
    const response = await csrfFetch("/api/users", {
      method: "POST",
      body: JSON.stringify({
        username,
        firstName,
        lastName,
        email,
        password,
      }),
    });
    const data = await response.json();
    dispatch(setUser(data.user));
    return response;
  };

  export const logout = () => async (dispatch) => {
    const response = await csrfFetch('/api/session', {
      method: 'DELETE',
    });
    dispatch(removeUser());
    return response;
  };

  const initialState = { user: null };

  const sessionReducer = (state = initialState, action) => {
    let newState;
    switch (action.type) {
      case SET_USER:
        newState = Object.assign({}, state);
        newState.user = action.payload;
        return newState;
      case REMOVE_USER:
        newState = Object.assign({}, state);
        newState.user = null;
        return newState;
      default:
        return state;
    }
  };

  export default sessionReducer;
                `
                ,
                function (err) {
                  if (err) throw err;
                  console.log("Writing session reducers");

                  fs.mkdir("frontend/src/components/LoginFormPage", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("frontend/src/components/LoginFormPage folder created successfully!");
                  });

                  fs.mkdir("frontend/src/components/SignupFormPage", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("src/components/SignupFormPage folder created successfully!");
                  });

                  fs.mkdir("frontend/src/components/Navigation", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("frontend/src/components/Navigation folder created successfully!");
                  });

                  fs.mkdir("frontend/src/context", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("frontend/src/context folder created successfully!");
                  });

                  fs.mkdir("frontend/src/components/OpenModalButton", (err) => {
                    if (err) {
                      return console.error(err);
                    }
                    console.log("frontend/src/components/OpenModalButton folder created successfully!");
                    fs.writeFile('frontend/src/components/SignupFormPage/index.js',
                  `
    import React, { useState } from "react";
    import { useDispatch, useSelector } from "react-redux";
    import { Redirect } from "react-router-dom";
    import * as sessionActions from "../../store/session";
    //import "./SignupForm.css";

    function SignupFormPage() {
      const dispatch = useDispatch();
      const sessionUser = useSelector((state) => state.session.user);
      const [email, setEmail] = useState("");
      const [username, setUsername] = useState("");
      const [firstName, setFirstName] = useState("");
      const [lastName, setLastName] = useState("");
      const [password, setPassword] = useState("");
      const [confirmPassword, setConfirmPassword] = useState("");
      const [errors, setErrors] = useState({});

      if (sessionUser) return <Redirect to="/" />;

      const handleSubmit = (e) => {
        e.preventDefault();
        if (password === confirmPassword) {
          setErrors({});
          return dispatch(
            sessionActions.signup({
              email,
              username,
              firstName,
              lastName,
              password,
            })
          ).catch(async (res) => {
            const data = await res.json();
            if (data && data.errors) {
              setErrors(data.errors);
            }
          });
        }
        return setErrors({
          confirmPassword: "Confirm Password field must be the same as the Password field"
        });
      };

      return (
        <>
          <h1>Sign Up</h1>
          <form onSubmit={handleSubmit}>
            <label>
              Email
              <input
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
            {errors.email && <p>{errors.email}</p>}
            <label>
              Username
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </label>
            {errors.username && <p>{errors.username}</p>}
            <label>
              First Name
              <input
                type="text"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
              />
            </label>
            {errors.firstName && <p>{errors.firstName}</p>}
            <label>
              Last Name
              <input
                type="text"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                required
              />
            </label>
            {errors.lastName && <p>{errors.lastName}</p>}
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
            {errors.password && <p>{errors.password}</p>}
            <label>
              Confirm Password
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </label>
            {errors.confirmPassword && <p>{errors.confirmPassword}</p>}
            <button type="submit">Sign Up</button>
          </form>
        </>
      );
    }

    export default SignupFormPage;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend signup form.");
                  })

                  fs.writeFile('frontend/src/components/Navigation/index.js',
                  `
    import React from 'react';
    import { NavLink } from 'react-router-dom';
    import { useSelector } from 'react-redux';
    import ProfileButton from './ProfileButton';
    //import './Navigation.css';

    function Navigation({ isLoaded }){
      const sessionUser = useSelector(state => state.session.user);

      let sessionLinks;
      if (sessionUser) {
        sessionLinks = (
          <li>
            <ProfileButton user={sessionUser} />
          </li>
        );
      } else {
        sessionLinks = (
          <li>
            <NavLink to="/login">Log In</NavLink>
            <NavLink to="/signup">Sign Up</NavLink>
          </li>
        );
      }

      return (
        <ul>
          <li>
            <NavLink exact to="/">Home</NavLink>
          </li>
          {isLoaded && sessionLinks}
        </ul>
      );
    }

    export default Navigation;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend navigation bar.");
                  })

                  fs.writeFile('frontend/src/components/Navigation/ProfileButton.js',
                  `
    import React, { useState, useEffect, useRef } from "react";
    import { useDispatch } from 'react-redux';
    import * as sessionActions from '../../store/session';

    function ProfileButton({ user }) {
      const dispatch = useDispatch();
      const [showMenu, setShowMenu] = useState(false);
      const ulRef = useRef();

      const openMenu = () => {
        if (showMenu) return;
        setShowMenu(true);
      };

      useEffect(() => {
        if (!showMenu) return;

        const closeMenu = (e) => {
          if (!ulRef.current.contains(e.target)) {
            setShowMenu(false);
          }
        };

        document.addEventListener('click', closeMenu);

        return () => document.removeEventListener("click", closeMenu);
      }, [showMenu]);

      const logout = (e) => {
        e.preventDefault();
        dispatch(sessionActions.logout());
      };

      const ulClassName = "profile-dropdown" + (showMenu ? "" : " hidden");

      return (
        <>
          <button onClick={openMenu}>
            <i className="fas fa-user-circle" />
          </button>
          <ul className={ulClassName} ref={ulRef}>
            <li>{user.username}</li>
            <li>{user.firstName} {user.lastName}</li>
            <li>{user.email}</li>
            <li>
              <button onClick={logout}>Log Out</button>
            </li>
          </ul>
        </>
      );
    }

    export default ProfileButton;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend profile button.");
                  })

                  fs.writeFile('frontend/src/context/Modal.js',
                  `
    import React, { useRef, useState, useContext } from "react";
    import ReactDOM from "react-dom";
    import "./Modal.css";

    const ModalContext = React.createContext();

    export default function ModalProvider({ children }) {
      const modalRef = useRef();
      const [modalContent, setModalContent] = useState(null);
      // callback function that will be called when modal is closing
      const [onModalClose, setOnModalClose] = useState(null);

      const closeModal = () => {
        setModalContent(null); // clear the modal contents
        // If callback function is truthy, call the callback function and reset it
        // to null:
        if (typeof onModalClose === "function") {
          setOnModalClose(null);
          onModalClose();
        }
      };

      const contextValue = {
        modalRef, // reference to modal div
        modalContent, // React component to render inside modal
        setModalContent, // function to set the React component to render inside modal
        setOnModalClose, // function to set the callback function called when modal is closing
        closeModal, // function to close the modal
      };

      return (
        <>
          <ModalContext.Provider value={contextValue}>
            {children}
          </ModalContext.Provider>
          <div ref={modalRef} />
        </>
      );
    }

    export function Modal() {
      const { modalRef, modalContent, closeModal } = useContext(ModalContext);
      // If there is no div referenced by the modalRef or modalContent is not a
      // truthy value, render nothing:
      if (!modalRef || !modalRef.current || !modalContent) return null;

      // Render the following component to the div referenced by the modalRef
      return ReactDOM.createPortal(
        <div id="modal">
          <div id="modal-background" onClick={closeModal} />
          <div id="modal-content">{modalContent}</div>
        </div>,
        modalRef.current
      );
    }

    export const useModal = () => useContext(ModalContext);
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend modal.");
                  })

                  fs.writeFile('frontend/src/context/Modal.css',
                  `
    #modal {
      position: fixed;
      top: 0;
      right: 0;
      left: 0;
      bottom: 0;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    #modal-background {
      position: fixed;
      top: 0;
      right: 0;
      left: 0;
      bottom: 0;
      background-color: rgba(0, 0, 0, 0.7);
    }

    #modal-content {
      position: absolute;
      background-color: white;
    }
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend modal css.");
                  })

                  fs.writeFile('frontend/src/components/OpenModalButton/index.js',
                  `
    import React from "react";
    import { useModal } from "../../context/Modal";

    function OpenModalButton({
      modalComponent, // component to render inside the modal
      buttonText, // text of the button that opens the modal
      onButtonClick, // optional: callback function that will be called once the button that opens the modal is clicked
      onModalClose, // optional: callback function that will be called once the modal is closed
    }) {
      const { setModalContent, setOnModalClose } = useModal();

      const onClick = () => {
        if (typeof onButtonClick === "function") onButtonClick();
        if (typeof onModalClose === "function") setOnModalClose(onModalClose);
        setModalContent(modalComponent);
      };

      return <button onClick={onClick}>{buttonText}</button>;
    }

    export default OpenModalButton;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend modal button.");
                  })
                  });

                  fs.writeFile('frontend/src/components/LoginFormPage/index.js',
                  `
    import React, { useState } from "react";
    import * as sessionActions from "../../store/session";
    import { useDispatch, useSelector } from "react-redux";
    import { Redirect } from "react-router-dom";
    //import "./LoginForm.css";

    function LoginFormPage() {
      const dispatch = useDispatch();
      const sessionUser = useSelector((state) => state.session.user);
      const [credential, setCredential] = useState("");
      const [password, setPassword] = useState("");
      const [errors, setErrors] = useState({});

      if (sessionUser) return <Redirect to="/" />;

      const handleSubmit = (e) => {
        e.preventDefault();
        setErrors({});
        return dispatch(sessionActions.login({ credential, password })).catch(
          async (res) => {
            const data = await res.json();
            if (data && data.errors) setErrors(data.errors);
          }
        );
      };

      return (
        <>
          <h1>Log In</h1>
          <form onSubmit={handleSubmit}>
            <label>
              Username or Email
              <input
                type="text"
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
            {errors.credential && <p>{errors.credential}</p>}
            <button type="submit">Log In</button>
          </form>
        </>
      );
    }

    export default LoginFormPage;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend login form.");
                  })

                  fs.writeFile('frontend/src/App.js',
                  `
    import React, { useState, useEffect } from "react";
    import { useDispatch } from "react-redux";
    import { Route, Switch } from "react-router-dom";
    import LoginFormPage from "./components/LoginFormPage";
    import SignupFormPage from "./components/SignupFormPage";
    import * as sessionActions from "./store/session";
    import Navigation from "./components/Navigation";

    function App() {
      const dispatch = useDispatch();
      const [isLoaded, setIsLoaded] = useState(false);
      useEffect(() => {
        dispatch(sessionActions.restoreUser()).then(() => setIsLoaded(true));
      }, [dispatch]);

      return (
        <>
          <Navigation isLoaded={isLoaded} />
          {isLoaded && (
            <Switch>
              <Route path="/login">
                <LoginFormPage />
              </Route>
              <Route path="/signup">
                <SignupFormPage />
              </Route>
            </Switch>
          )}
        </>
      );
    }

    export default App;
                  `
                  ,
                  function (err) {
                    if (err) throw err;
                    console.log("Writing frontend App.js");
                  })


                })

                })


              })
            });

          })
        })
      })
    })

  });
});

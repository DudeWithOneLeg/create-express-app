#! /usr/bin/env node

const fs = require("fs");
const util = require("util");
const exec = util.promisify(require("child_process").exec);

// Specify the directory where you want to run the command
const directoryPath = "backend";

// The command you want to execute
const command =
  "npm init -y && npm install cookie-parser cors csurf dotenv express express-async-errors helmet jsonwebtoken morgan per-env sequelize@6 sequelize-cli@6 pg bcryptjs && npm install -D sqlite3 dotenv-cli nodemon";

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
  exec(command, options, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return callback(error);
    }
    console.log("stdout:", stdout);
    console.log("stderr:", stderr);

    callback(null);
  });
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
    console.log("stdout:", stdout); // Output from the npm install command
    console.log("stderr:", stderr); // Error messages, if any
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
      console.log("Saved!");
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
      console.log("Saved!");
    }
  );

  exec("pwd", options, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log("stdout: pwd", stdout); // Output from the npm install command
    console.log("stderr:", stderr); // Error messages, if any
  });

  // Once `sequelize init` is complete, run `sequelize db:migrate` command
  runCommand("npx sequelize init", options, (error) => {
    if (error) {
      console.error("Failed to run sequelize db:migrate command.");
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
        console.log("Saved!");
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
        console.log("Saved!");
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
        console.log("Saved!");
      }
    );

    fs.mkdir("backend/routes", (err) => {
      if (err) {
        return console.error(err);
      }
      console.log("Routes folder created successfully!");
    });

    exec("pwd", options, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return;
      }
      console.log("stdout:", stdout); // Output from the npm install command
      console.log("stderr:", stderr); // Error messages, if any
    });

    fs.writeFile(
      "backend/routes/index.js",
      `
const express = require('express')
const router = express.Router()
const apiRouter = require('./api');

router.use('/api', apiRouter);

router.get("/api/csrf/restore", (req, res) => {
  const csrfToken = req.csrfToken();
  res.cookie("XSRF-TOKEN", csrfToken);
  res.status(200).json({
    'XSRF-Token': csrfToken
  });
});

module.exports = router;`,
      function (err) {
        if (err) throw err;
        console.log("Saved!");
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
      console.log("stdout: pwd", stdout); // Output from the npm install command
      console.log("stderr:", stderr); // Error messages, if any
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
        console.log("Saved!");
      }
    );

    console.log("sequelize db:migrate command completed successfully.");

    fs.mkdir("backend/routes/api", (err) => {
      if (err) {
        return console.error(err);
      }
      console.log("api folder created successfully!");
    });
    exec("pwd", (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error}`);
        return;
      }
      console.log("stdout: pwd", stdout); // Output from the npm install command
      console.log("stderr:", stderr); // Error messages, if any
    });

    fs.writeFile(
      "backend/routes/api/index.js",
      `
const router = require('express').Router();

router.post('/test', function(req, res) {
  res.json({ requestBody: req.body });
});

module.exports = router;
`,
      function (err) {
        if (err) throw err;
        console.log("Saved!");
      }
    );
    runCommand("npx sequelize model:generate --name User --attributes username:string,email:string,hashedPassword:string", options, (error) => {
      if (error) {
        console.error("Failed to generate Users model.");
        return;
      }
      const files = fs.readdirSync('./backend/db/migrations');
      fs.writeFile(
        `backend/db/migrations/${files[0]}`,
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
          console.log("Saved!");
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
          console.log("Saved!");
        }
      );
      runCommand("npx dotenv sequelize db:migrate", options, (error) => {
        if (error) {
          console.error("Failed to generate Users model.");
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
          console.log("api folder created successfully!");
        });
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
            console.log("Saved!");
          }
        );
      })
    })

  });
});

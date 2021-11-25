const path = require("path");
const util = require("util");
const open = require("open");

const winston = require("winston");

const Boom = require("boom");
const Hapi = require("@hapi/hapi");
const Vision = require("@hapi/vision");
const Inert = require("@hapi/inert");
const Handlebars = require("handlebars");
const Joi = require("joi");
const Q = require("q");

const porter = require("./porter");

const fs = require("fs");
const dotenv = require("dotenv-defaults");

const forge = require("node-forge");
const { exist } = require("joi");
const { info } = require("console");

// global vars
let config;
let logger;
let server;

function getPath(p) {
  return path.join(__dirname, p);
}

function loadConfig() {
  logger.info("Loading config");
  config = dotenv.config().parsed;
}

function doKeysExist() {
  logger.info("Testing for existing https keypair");

  let ret = true;

  if (!fs.existsSync(getPath(config.HTTPS_KEY_FILE))) {
    logger.info("Private key file does not exist, will generate new keypair");
    ret = false;
  }

  if (!fs.existsSync(getPath(config.HTTPS_CERT_FILE))) {
    logger.info(
      "Public certificate file does not exist, will generate new keypair"
    );
    ret = false;
  }

  return ret;
}

function writeKeypair() {
  logger.info("Writing new public/private keypair");
  fs.writeFileSync(getPath(config.HTTPS_KEY_FILE), config.HTTPS_KEY);
  fs.writeFileSync(getPath(config.HTTPS_CERT_FILE), config.HTTPS_CERT);
}

function generateKeypair() {

  if (doKeysExist()) {
    logger.info("Keypair exists, not generating new keys");
    return;
  }

  logger.info("Generating new keypair");

  var keys = forge.pki.rsa.generateKeyPair(2048);
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;

  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date().addDays(30);
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  var attrs = [
    {
      name: "commonName",
      value: "SlackPorter",
    },
    {
      name: "organizationName",
      value: "SlackPorter",
    },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: true,
    },
    {
      name: "nsCertType",
      server: true,
    },
    {
      name: "subjectAltName",
      altNames: [
        {
          type: 7, // IP
          ip: "127.0.0.1",
        },
      ],
    },
    {
      name: "subjectKeyIdentifier",
    },
  ]);

  // self-sign certificate
  cert.sign(keys.privateKey);

  // convert Forge certificates to PEM
  config.HTTPS_CERT = forge.pki.certificateToPem(cert);
  config.HTTPS_KEY = forge.pki.privateKeyToPem(keys.privateKey);

  writeKeypair();
}

function retrieveKeypair() {
  logger.info("Retrieving keypair");
  config.HTTPS_KEY = fs.readFileSync(config.HTTPS_KEY_FILE, "utf8");
  config.HTTPS_CERT = fs.readFileSync(config.HTTPS_CERT_FILE, "utf8");
}

function configureLogging() {
  const consoleformat = winston.format.printf(
    ({ level, message, label, timestamp }) => {
      return `${timestamp} [${label}] ${level}: ${JSON.stringify(
        message,
        null,
        4
      )}`;
    }
  );

  const timezoned = () => {
    return new Date().toLocaleString("en-US", {
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    });
  };

  const conf = {
    transports: [
      new winston.transports.Console({
        level: config?.LOG_LEVEL || "info",
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
          winston.format.label({ label: "slackporter" }),
          consoleformat
        ),
      }),
    ],
  };

  if (config?.LOG_FILE) {
    conf.transports.push(
      new winston.transports.File({
        filename: getPath(config.LOG_FILE),
        level: config.LOG_LEVEL || "info",
      })
    );
  }

  logger = winston.createLogger(conf);
}

async function configureServer() {
  logger.info("Configuring server");

  console.log(config.HTTPS_KEY_FILE);
  console.log(config.HTTPS_KEY);
  console.log(config.HTTPS_CERT_FILE);
  console.log(config.HTTPS_CERT);

  var fromUserSchema = Joi.object().keys({
    url: Joi.string()
      .uri()
      .regex(/^https:\/\/.*\.slack\.com\/?$/)
      .required(),
    token: Joi.string().allow(""),
    emojiJson: Joi.string().allow(""),
  });

  var toUserSchema = Joi.object().keys({
    url: Joi.string()
      .uri()
      .regex(/^https:\/\/.*\.slack\.com\/?$/)
      .required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    token: Joi.string().required(),
  });

  var loginSchema = Joi.object().keys({
    userFrom: fromUserSchema,
    userTo: toUserSchema,
  });

  var transferSchema = Joi.object().keys({
    userFrom: fromUserSchema,
    userTo: toUserSchema,
    emojiName: Joi.string().required(),
    emojiUrl: Joi.string().uri().required(),
  });

  // Just guessing at what reasonable rate limits should be.
  var rateLimiter = {};
  var MAX_REQUESTS = 10;
  var RATE_INTERVAL = 2000;

  setInterval(function () {
    rateLimiter = {};
  }, RATE_INTERVAL);

  // create the https server @hapi/hapi
  server = Hapi.server({
    port: config.HTTPS_PORT,
    host: config.HTTPS_HOST,
    tls: { key: config.HTTPS_KEY, cert: config.HTTPS_CERT },
  });

  // use the @hapi/vision module to add template rendering support to hapi
  await server.register(Vision);

  // use Handlebars for the actual rendering
  server.views({
    compileMode: "async",
    engines: {
      html: {
        module: Handlebars,
        compileMode: "sync",
      },
    },
    relativeTo: __dirname,
    path: "templates",
  });

  // use the @hapi/inert module for static resources
  await server.register(Inert);

  // configure a route for the inert module
  server.route([
    {
      method: "GET",
      path: "/static/{param*}",
      handler: {
        directory: {
          path: "static",
        },
      },
    },
  ]);

  // set up routes for the rest of the functionality
  server.route([
    {
      method: "GET",
      path: "/",
      handler: function (request, reply) {
        return reply.view("index");
      },
    },
    {
      method: "POST",
      path: "/emojilist",
      config: {
        validate: {
          payload: loginSchema,
        },
      },
      handler: function (request, reply) {
        rateLimiter[request.info.remoteAddress] =
          rateLimiter[request.info.remoteAddress] + 1 || 1;
        if (rateLimiter[request.info.remoteAddress] > MAX_REQUESTS) {
          return reply(Boom.tooManyRequests("too many requests"));
        }

        var userFrom = request.payload.userFrom;
        var userTo = request.payload.userTo;

        if (!userFrom.token && !userFrom.emojiJson) {
          return reply(
            Boom.badRequest("You must enter either a token or a JSON response.")
          );
        }

        request.payload.userFrom.info = request.info;
        request.payload.userTo.info = request.info;

        var fromPromise = porter.fetchEmojiList(request.payload.userFrom);

        var toPromise = porter
          .getLoginPage(request.payload.userTo)
          .then(porter.postLoginPage)
          .then(porter.fetchEmojiList);

        Q.all([fromPromise, toPromise]).then(
          function (results) {
            try {
              for (var e in results[1].emoji) {
                delete results[0].emoji[e];
              }
              reply.view("emojis", { emoji: results[0].emoji });
            } catch (error) {
              winston.error("emojilist Error:\n" + util.inspect(error));
              reply(Boom.badImplementation("Internal Server Error"));
            }
          },
          function (error) {
            winston.error(
              "emojilist all handler Error:\n" + util.inspect(error)
            );
            if (error.statusCode) {
              switch (error.statusCode) {
                case 404:
                  reply(Boom.notFound("Team page not found for " + error.url));
                  break;
                case 401:
                  reply(Boom.unauthorized("Invalid password for " + error.url));
                  break;
              }
            } else {
              reply(Boom.badImplementation("Internal Server Error"));
            }
          }
        );
      },
    },
    {
      method: "POST",
      path: "/transferEmoji",
      config: {
        validate: {
          payload: transferSchema,
        },
      },
      handler: function (request, reply) {
        rateLimiter[request.info.remoteAddress] =
          rateLimiter[request.info.remoteAddress] + 1 || 1;
        if (rateLimiter[request.info.remoteAddress] > MAX_REQUESTS) {
          return reply(Boom.tooManyRequests("too many requests"));
        }

        request.payload.userTo.info = request.info;

        porter
          .getLoginPage(request.payload.userTo)
          .then(porter.postLoginPage)
          .then(porter.getEmojiUploadPage)
          .then(function (options) {
            return porter.transferEmoji(
              options,
              request.payload.emojiName,
              request.payload.emojiUrl
            );
          })
          .then(function () {
            reply({ success: true });
          })
          .fail(function (error) {
            winston.error("/transferEmoji error:\n", util.inspect(error));
            reply(Boom.badImplementation("Internal Server Error"));
          });
      },
    },
  ]);

  logger.info("end configure server");
}

async function startServer() {
  logger.info("Starting server");
  await server.start();
  logger.info(`Server running at: ${server.info.uri}`);
  await open(server.info.uri);
}

async function main() {
  // initialise basic logging
  configureLogging();
  // load config from dotenv
  loadConfig();
  // re-configure logging if config specifies different logging levels
  configureLogging();
  // generate public/private keys (skip if they already exist)
  generateKeypair();
  retrieveKeypair();
  // configure the http(s) server
  await configureServer();
  // start listening for http/https connections
  await startServer();
}

main();

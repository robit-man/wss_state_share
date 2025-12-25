const fs = require('fs');
const https = require('https');
const http = require('http');
const CERT = "/home/robit/Documents/repositories/phone-twins-mkcert-https/certs/cert.pem";
const KEY  = "/home/robit/Documents/repositories/phone-twins-mkcert-https/certs/key.pem";

// Force HTTPS when app uses http.createServer(...)
const _create = http.createServer;
http.createServer = function (opts, listener) {
  if (typeof opts === 'function') listener = opts;
  return https.createServer({ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }, listener);
};
const _Server = http.Server;
http.Server = function (...args) {
  return https.Server({ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }, ...args);
};
http.Server.prototype = _Server.prototype;

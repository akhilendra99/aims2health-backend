const helmet = require("helmet");

const contentSecurityPolicy = {
  useDefaults: false,
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    scriptSrcAttr: ["'none'"],
    styleSrc: ["'self'"],
    styleSrcAttr: ["'none'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    mediaSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: ["'none'"],
    frameSrc: ["'none'"],
    formAction: ["'self'"],
  },
};

const helmetMiddleware = helmet({
  contentSecurityPolicy,
  // HSTS is applied below only after Express determines the request is secure.
  hsts: false,
  frameguard: { action: "deny" },
  noSniff: true,
  hidePoweredBy: true,
  // The frontend and backend use sibling hosts; this allows same-site file
  // delivery while preventing unrelated sites from embedding backend files.
  crossOriginResourcePolicy: { policy: "same-site" },
});

module.exports = function securityHeaders(req, res, next) {
  // This backend serves dynamic APIs and access-controlled files, not public
  // fingerprinted assets. Do not cache login, authenticated, or error bodies.
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  helmetMiddleware(req, res, error => {
    if (error) return next(error);
    if (req.secure) {
      // Keep HSTS to this host until every subdomain has been verified for
      // HTTPS. Do not enable includeSubDomains or preload from repo evidence.
      res.setHeader("Strict-Transport-Security", "max-age=31536000");
    } else {
      res.removeHeader("Strict-Transport-Security");
    }
    next();
  });
};

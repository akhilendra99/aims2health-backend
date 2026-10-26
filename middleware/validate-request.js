const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ID_PATTERN = /^[1-9]\d*$/;
const invalid = message => ({ validationError: message });
const fs = require("fs");

function discardUploadedFile(req) {
  if (!req.file?.path) return;
  try { fs.unlinkSync(req.file.path); } catch { /* The file may already have been removed. */ }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validateValue(value, rule) {
  if (value === null) return rule.nullable ? { value: null } : invalid("must not be null");

  let normalized = value;
  if (rule.type === "string" || rule.type === "phone" || rule.type === "digits" || rule.type === "email" || rule.type === "date" || rule.type === "dateOrYear") {
    if (rule.type === "phone" || rule.type === "digits") {
      if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) value = String(value);
      if (typeof value !== "string") return invalid("must be a string or integer");
    }
    if (rule.type === "dateOrYear" && typeof value === "number" && Number.isSafeInteger(value) && value >= 0) value = String(value);
    if (typeof value !== "string") return invalid("must be a string");
    normalized = value;
    if (value === "" && rule.allowEmpty) return { value };
    if (rule.nonEmpty && value.trim() === "") return invalid("must not be empty");
    if (rule.maxLength !== undefined && value.length > rule.maxLength) return invalid(`must be at most ${rule.maxLength} characters`);
    if (rule.maxBytes !== undefined && Buffer.byteLength(value, "utf8") > rule.maxBytes) return invalid("is too long");
    if (rule.pattern && !rule.pattern.test(value)) return invalid("has an invalid format");
    if (rule.type === "digits" && !/^\d+$/.test(value)) return invalid("must contain digits only");
    if (rule.type === "email" && (!EMAIL_PATTERN.test(value) || value.length > 254)) return invalid("must be a valid email address");
    if (rule.type === "date" && !isDateOnly(value)) return invalid("must be a valid YYYY-MM-DD date");
    if (rule.type === "dateOrYear") {
      const yearOnly = /^\d{4}$/.test(value);
      if (yearOnly) {
        const year = Number(value);
        if (year < (rule.minYear || 1900) || year > (rule.maxYear || new Date().getFullYear())) return invalid("must be a valid date or four-digit year");
      } else if (/^\d{1,3}$/.test(value)) {
        const age = Number(value);
        if (age > 120) return invalid("must be an age from 0 to 120");
      } else if (!isDateOnly(value)) {
        return invalid("must be a valid date or four-digit year");
      }
    }
  } else if (rule.type === "id" || rule.type === "integer") {
    const text = typeof value === "number" && Number.isSafeInteger(value) ? String(value) : value;
    if (typeof text !== "string" || !(rule.type === "id" ? ID_PATTERN : /^(0|[1-9]\d*)$/).test(text)) return invalid(rule.type === "id" ? "must be a positive integer" : "must be a non-negative integer");
    const number = Number(text);
    if (!Number.isSafeInteger(number)) return invalid("is outside the supported range");
    if (rule.min !== undefined && number < rule.min) return invalid(`must be at least ${rule.min}`);
    if (rule.max !== undefined && number > rule.max) return invalid(`must be at most ${rule.max}`);
    normalized = number;
  } else {
    return invalid("has an invalid validation schema");
  }

  if (rule.values && !rule.values.includes(normalized)) return invalid("has an unsupported value");
  return { value: normalized };
}

function validateObject(sourceName, input, schema, allowUnknown, errors) {
  if (!isPlainObject(input)) {
    errors.push({ field: sourceName, message: "must be an object" });
    return {};
  }

  const output = {};
  if (!allowUnknown) {
    for (const key of Object.keys(input)) {
      if (!Object.prototype.hasOwnProperty.call(schema, key)) errors.push({ field: `${sourceName}.${key}`, message: "is not allowed" });
    }
  }

  for (const [key, rule] of Object.entries(schema)) {
    if (!Object.prototype.hasOwnProperty.call(input, key) || input[key] === undefined) {
      if (rule.required) errors.push({ field: `${sourceName}.${key}`, message: "is required" });
      continue;
    }
    const result = validateValue(input[key], rule);
    if (Object.prototype.hasOwnProperty.call(result, "validationError")) {
      errors.push({ field: `${sourceName}.${key}`, message: result.validationError });
    } else {
      output[key] = result.value;
    }
  }
  return output;
}

function validateRequest({ body, query, params, allowUnknown = false, refine } = {}) {
  return (req, res, next) => {
    const errors = [];
    const validated = {};
    if (body) validated.body = validateObject("body", req.body ?? {}, body, allowUnknown, errors);
    if (query) validated.query = validateObject("query", req.query ?? {}, query, allowUnknown, errors);
    if (params) validated.params = validateObject("params", req.params ?? {}, params, allowUnknown, errors);
    if (refine) errors.push(...(refine(validated) || []));

    if (errors.length) {
      discardUploadedFile(req);
      return res.status(400).json({ message: "Invalid request.", errors });
    }
    req.validatedRequest = { ...req.validatedRequest, ...validated };
    return next();
  };
}

function validateUploadedFile({ optional = true, maxBytes, mimeTypes } = {}) {
  return (req, res, next) => {
    const file = req.file;
    if (!file) {
      if (!optional) return res.status(400).json({ message: "Invalid request.", errors: [{ field: "file", message: "is required" }] });
      return next();
    }
    if (typeof file.originalname !== "string" || !file.originalname || file.originalname.length > 255) {
      discardUploadedFile(req);
      return res.status(400).json({ message: "Invalid upload.", errors: [{ field: "file", message: "has an invalid filename" }] });
    }
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > maxBytes) {
      discardUploadedFile(req);
      return res.status(400).json({ message: "Invalid upload.", errors: [{ field: "file", message: "exceeds the allowed size" }] });
    }
    if (!mimeTypes.includes(file.mimetype)) {
      discardUploadedFile(req);
      return res.status(400).json({ message: "Invalid upload.", errors: [{ field: "file", message: "has an unsupported media type" }] });
    }
    return next();
  };
}

module.exports = { validateRequest, validateUploadedFile, isDateOnly };

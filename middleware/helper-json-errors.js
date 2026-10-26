module.exports = function helperJsonErrors(err, req, res, next) {
  const isHelperApi = req.originalUrl === "/api/helper" || req.originalUrl.startsWith("/api/helper/");
  if (isHelperApi && err && err.type === "entity.parse.failed" && err.status === 400) {
    return res.status(400).json({ message: "Invalid request.", errors: [{ field: "body", message: "must contain valid JSON" }] });
  }
  return next(err);
};

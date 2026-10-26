// Validates and clamps pagination query params before they are used to
// build a SQL LIMIT clause, so unvalidated input never reaches the query
// (previously pagesize/page were coerced with unary + and concatenated
// straight into the SQL string, which could yield NaN,NaN or, with a
// malicious query string, values outside any expected range).
function buildLimit(pagesize, page) {
  const numPerPage = Math.max(1, Math.min(100, parseInt(pagesize, 10) || 20));
  const currentPage = Math.max(1, parseInt(page, 10) || 1);
  const skip = (currentPage - 1) * numPerPage;
  return { limit: `${skip},${numPerPage}`, numPerPage, currentPage };
}

module.exports = { buildLimit };

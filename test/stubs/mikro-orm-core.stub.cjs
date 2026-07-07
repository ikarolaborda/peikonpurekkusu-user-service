// ESM-only in production; unit tests only need pass-through shapes.
module.exports = {
  defineEntity: (meta) => meta,
};

exports.create = function(__helpers) {
  var str = __helpers.s,
      empty = __helpers.e,
      notEmpty = __helpers.ne,
      escapeXml = __helpers.x;

  return function render(data, out) {
    var escapeXml = out.global.escapeSQL,
        params = data.params,
        t = data.t;

    out.w('UPDATE\n    tUsers\nSET\n    RetriesLeft = CASE @retries WHEN 0 THEN 3 ELSE @retries END,\n    UserHash = ' +
      escapeXml(params.userHash) +
      '\nWHERE\n    userId=' +
      escapeXml(params.userId));
  };
}
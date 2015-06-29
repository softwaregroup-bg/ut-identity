exports.create = function(__helpers) {
  var str = __helpers.s,
      empty = __helpers.e,
      notEmpty = __helpers.ne,
      escapeXml = __helpers.x;

  return function render(data, out) {
    var escapeXml = out.global.escapeSQL,
        params = data.params,
        t = data.t;

    out.w('DELETE FROM tUserSessions WHERE UserID=' +
      escapeXml(params.userId));
  };
}
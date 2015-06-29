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
      escapeXml(params.userId) +
      '\n\nINSERT INTO\n    tUserSessions(Cookie,UTSessionID,UserID,Expire,[Module],[Language],RemoteIP,UserAgent,DateCreated)\nOUTPUT\n    inserted.Module,\n    inserted.UTSessionID,\n    inserted.Cookie _Cookie,\n    0 _ErrorCode,\n    \'true\' CreateSession\nVALUES\n    (CONVERT(VARCHAR(36), newid())+\'/\'+' +
      escapeXml(params._random) +
      ',CONVERT(VARCHAR(36), newid()),' +
      escapeXml(params.userId) +
      ',DATEADD(second,CAST(' +
      escapeXml(params._SessionTimeout) +
      ' AS INT),GetDate()),LEFT(' +
      escapeXml(params.module) +
      ',50),LEFT(' +
      escapeXml(params.language) +
      ',3),LEFT(' +
      escapeXml(params._remoteip) +
      ',50),LEFT(' +
      escapeXml(params._Header_User-Agent) +
      ',500),GetDate())');
  };
}
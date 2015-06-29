exports.create = function(__helpers) {
  var str = __helpers.s,
      empty = __helpers.e,
      notEmpty = __helpers.ne,
      escapeXml = __helpers.x;

  return function render(data, out) {
    var escapeXml = out.global.escapeSQL,
        params = data.params,
        t = data.t;

    out.w('DECLARE\n\t\t@sessionId nvarchar(max),\n        @userId bigint,\n        @language nvarchar(50),\n        @Result bigint,\n        @ResultMessage nvarchar(max)\n\nEXEC [utIdentity].[Check]\n        @currentSessionId = ' +
      escapeXml(params.sessionId) +
      ',\n        @username = ' +
      escapeXml(params.username) +
      ',\n        @password = ' +
      escapeXml(params.password) +
      ',\n        @ImplementationID = ' +
      escapeXml(params.implementation) +
      ',\n        @IsUpdateAllowed = true,\n        @sessionId = @sessionId OUTPUT,\n        @userId = @userId OUTPUT,\n        @language = @language OUTPUT,\n        @Result = @Result OUTPUT,\n        @ResultMessage = @ResultMessage OUTPUT\n\nSELECT\n        @Result as Result,\n        @ResultMessage as ResultMessage,\n        @sessionId as sessionId,\n        @language as language,\n        @userId as userId');
  };
}
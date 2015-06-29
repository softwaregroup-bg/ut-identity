exports.create = function(__helpers) {
  var str = __helpers.s,
      empty = __helpers.e,
      notEmpty = __helpers.ne,
      escapeXml = __helpers.x;

  return function render(data, out) {
    var escapeXml = out.global.escapeSQL,
        params = data.params,
        t = data.t;

    out.w('DECLARE\n    @retriesleft INT,\n    @useractive BIT,\n    @passwordexpired BIT,\n    --@checkip BIT,\n    @checkuserpassword BIT,\n    @retries INT,\n    @expirationdays INT,\n    @userid INT\n\nSET @retriesleft=0\nSELECT\n    @userid=u.userid,\n    @retriesleft=IsNull(u.retriesleft,0),\n    @useractive=IsNull(u.useractive,0),\n    @passwordexpired=CASE WHEN GetDate()>=IsNull(u.PasswordExpiration,GetDate()) THEN 1 ELSE 0 END,\n    --@checkip=CASE ' +
      escapeXml(params.CheckUserRightsIP) +
      ' WHEN \'true\' THEN 1 ELSE 0 END,\n    @checkuserpassword=CASE WHEN IsNull(UserHash,\'\')!=\'\' AND IsNull(UserHash,\'\')=' +
      escapeXml(params.passwordhash) +
      ' THEN 1 ELSE 0 END,\n    @retries = IsNull(s1.SettingValue,0),\n    @expirationdays = IsNull(s2.SettingValue,0)\nFROM\n    tUsers u\nLEFT JOIN\n    tSettings s1 ON s1.SettingModule=' +
      escapeXml(params._implementation) +
      ' AND s1.SettingName=\'login_retries_limit\'\nLEFT JOIN\n    tSettings s2 ON s2.SettingModule=' +
      escapeXml(params._implementation) +
      ' AND s2.SettingName=\'password_expiration_days\'\nWHERE\n    UserLogin=' +
      escapeXml(params.username) +
      '\n\nDELETE FROM tUserSessions WHERE Expire<=GetDate() 0 IF @userid is null BEGIN SELECT \'User not found\' errorMessage, \'identity.notFound\' errorCode RETURN END>=@retriesleft\nBEGIN\n    SELECT\n        \'User account is suspended\' errorMessage,\n        \'identity.suspended\' errorCode\n    RETURN\nEND\nIF @checkuserpassword=1\nBEGIN\n    --IF @checkip=0\n    --BEGIN\n    --    SELECT\n    --        \'Invalid username or password\' errorPrint,\n    --        \'User not allowed from that IP\' errorMessage,\n    --        \'2005\' errorCode,\n    --        \'badip\' errorPage\n    --END ELSE\n    IF @useractive=0\n    BEGIN\n        SELECT\n            \'User is nonexisting or inactive\' errorMessage,\n            \'identity.notActiveOrNa\' errorCode\n    END ELSE\n    IF @passwordexpired=1 AND @expirationdays>0\n    BEGIN\n        IF ' +
      escapeXml(params.passwordnew) +
      '=\'\'\n        BEGIN\n            SELECT\n                \'User password expired\' errorMessage,\n                \'identity.passwordExpired\' errorCode\n            RETURN\n        END\n        IF ' +
      escapeXml(params.passwordnew) +
      '!=' +
      escapeXml(params.passwordrepeat) +
      '\n        BEGIN\n            SELECT\n                \'Retyped password does not match\' errorMessage,\n                \'identity.passwordNotSame\' errorCode\n            RETURN\n        END\n\n        IF object_id(\'switch.validatepassword\')>0\n        BEGIN\n            DECLARE @vp BIT\n            EXEC @vp = switch.validatepassword @UserName = ' +
      escapeXml(params.username) +
      ', @Password = ' +
      escapeXml(params.passwordnew) +
      ', @PasswordHash=' +
      escapeXml(params.PasswordHashNew) +
      '\n            if @vp!=1 return\n        END\n\n        UPDATE\n            tUsers\n        SET\n            RetriesLeft = CASE @retries WHEN 0 THEN 3 ELSE @retries END,\n            UserHash = ' +
      escapeXml(params.PasswordHashNew) +
      ',\n            PasswordExpiration = DATEADD(day,@expirationdays,DATEDIFF(day,0,GetDate()))\n        WHERE\n            userlogin=' +
      escapeXml(params.username) +
      '\n\n        IF ' +
      escapeXml(params._SingleUserSession) +
      '=\'true\'\n        BEGIN\n            DELETE FROM tUserSessions WHERE UserID=@userid\n        END\n\n        INSERT INTO\n            tUserSessions(Cookie,UTSessionID,UserID,Expire,[Module],[Language],RemoteIP,UserAgent,DateCreated)\n        OUTPUT\n            inserted.Module,\n            inserted.UTSessionID,\n            inserted.Cookie _Cookie,\n            0 errorCode,\n            \'true\' CreateSession\n        VALUES\n            (CONVERT(VARCHAR(36), newid())+\'/\'+' +
      escapeXml(params._random) +
      ',CONVERT(VARCHAR(36), newid()),@userid,DATEADD(second,CAST(' +
      escapeXml(params._SessionTimeout) +
      ' AS INT),GetDate()),LEFT(' +
      escapeXml(params.module) +
      ',50),LEFT(' +
      escapeXml(params.language) +
      ',3),LEFT(' +
      escapeXml(params._remoteip) +
      ',50),LEFT(' +
      escapeXml(params._Header_User-Agent) +
      ',500),GetDate())\n    END ELSE\n    BEGIN\n        UPDATE\n            tUsers\n        SET\n            RetriesLeft = CASE @retries WHEN 0 THEN 3 ELSE @retries END\n        WHERE\n            userlogin=' +
      escapeXml(params.username) +
      '\n\n        IF ' +
      escapeXml(params._SingleUserSession) +
      '=\'true\'\n        BEGIN\n            DELETE FROM tUserSessions WHERE UserID=@userid\n        END\n\n        INSERT INTO\n            tUserSessions(Cookie,UTSessionID,UserID,Expire,[Module],[Language],RemoteIP,UserAgent,DateCreated)\n        OUTPUT\n            inserted.Module,\n            inserted.UTSessionID,\n            inserted.Cookie _Cookie,\n            0 errorCode,\n            \'true\' CreateSession\n        VALUES\n            (CONVERT(VARCHAR(36), newid())+\'/\'+' +
      escapeXml(params._random) +
      ',CONVERT(VARCHAR(36), newid()),@userid,DATEADD(second,CAST(' +
      escapeXml(params._SessionTimeout) +
      ' AS INT),GetDate()),LEFT(' +
      escapeXml(params.module) +
      ',50),LEFT(' +
      escapeXml(params.language) +
      ',3),LEFT(' +
      escapeXml(params._remoteip) +
      ',50),LEFT(' +
      escapeXml(params._Header_User-Agent) +
      ',500),GetDate())\n    END\nEND ELSE\nBEGIN\n    --IF @checkip=1\n    --BEGIN\n    --   UPDATE\n    --        tUsers\n    --    SET\n    --        @RetriesLeft = RetriesLeft = CASE WHEN IsNull(RetriesLeft,0)>0 THEN RetriesLeft - 1 ELSE 0 END\n    --    WHERE\n    --        UserLogin=' +
      escapeXml(params.username) +
      '\n\n    --    SELECT\n    --        \'Invalid username or password\' errorPrint,\n    --        CASE WHEN @RetriesLeft>0 THEN \'Wrong password. Attempts LEFT:\'+cast(@RetriesLeft AS varchar) ELSE \'Wrong password. Your account was suspended.\' END  errorMessage,\n    --        \'2007\' errorCode,\n    --        \'wrong\' errorPage\n    --END ELSE\n    --BEGIN\n        SELECT\n            \'User is nonexisting or inactive\' errorMessage,\n            \'identity.notActiveOrNa\' errorCode\n    --END\nEND</=GetDate()>');
  };
}
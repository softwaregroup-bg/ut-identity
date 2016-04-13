ALTER PROCEDURE [identity].[check]
     @username NVARCHAR(200),
     @password varchar(max),
     @type varchar(max)
AS

SET NOCOUNT ON;

IF (@type = 'user/pass') BEGIN
    EXEC [identity].[check.userPassword] @username=@username, @password=@password
END ELSE IF (@type = 'session') BEGIN
    raiserror('identity.notImplemented', 16, 1);
END ELSE IF (@type = 'bio') BEGIN
    raiserror('identity.notImplemented', 16, 1);
END

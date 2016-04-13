ALTER PROCEDURE [identity].[check.userPassword]
     @username NVARCHAR(200),
     @password varchar(max)
AS

SET NOCOUNT ON;

BEGIN TRY
    DECLARE @UserID BIGINT,
            @UserPassword NVARCHAR(max),
            @LoginAttempts INT,
            @MaxLoginAttempts INT = 3, 
            @IsEnabled BIT = 0
            
    SELECT 
        @UserID = h.actorId,
        @UserPassword = h.value,
        @LoginAttempts = h.failedAttempts,
        @IsEnabled = h.isEnabled
    FROM [user].[hash] AS h      
    WHERE h.identifier = @UserName AND h.[type] = 'password'

    -- check if the @UserID exists for this @UserName
    IF @UserID IS NULL
    BEGIN
        raiserror('identy.invalid.credentials', 16, 1);
    END
    --check if this credential is already locked
    IF @IsEnabled = 0
    BEGIN
        raiserror('identy.disabled.credentials', 16, 1);
    END

    -- the Passwords do not match. If so, increment LoginAttempts
    IF @UserID IS NOT NULL AND @UserPassword <> @Password
    BEGIN
        IF @LoginAttempts + 1 >= @MaxLoginAttempts -- In this case we need to lock this credential.
            SET @IsEnabled = 0
           
        UPDATE [user].[hash]
            SET failedAttempts = @LoginAttempts + 1,
                isEnabled = @IsEnabled
        WHERE identifier = @UserName AND [type] = 'password'

        IF @IsEnabled = 0
        BEGIN
            raiserror('identity.the.credentials.locked', 16, 1);
        END
        ELSE
        BEGIN
            raiserror('identity.wrong.password', 16, 1);
        END
    END

    IF @LoginAttempts > 0
    BEGIN
        UPDATE [user].[hash]
            SET failedAttempts = 0,
            lastAttempt = getdate()
        WHERE identifier = @UserName AND [type] = 'password'
    END

    SELECT actorId
    FROM [user].hash
    WHERE identifier=@username and type = 'password'
               
    RETURN      
END TRY
BEGIN CATCH
    declare @errorMessage nvarchar(1000) = ERROR_MESSAGE(), @errorSeverity int = ERROR_SEVERITY(), @errorState int = ERROR_STATE()
    DECLARE @errorInfo NVARCHAR(MAX) = ''
    EXEC [identity].[ErrorInfoGet] @errorInfo OUTPUT
        
    -- INSERT INTO [identity].[_ErrorLog](ErrorInfo, Params)
    SELECT @errorInfo, 'userName: '+ @username +' password: '+ @password 
    
    raiserror(@errorMessage, @errorSeverity, @errorState);
END CATCH
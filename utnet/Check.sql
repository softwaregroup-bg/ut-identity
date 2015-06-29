CREATE PROCEDURE [utIdentity].[Check]
     @userName NVARCHAR(50)
    ,@password NVARCHAR(150)
    ,@currentSessionId NVARCHAR(50)  
    ,@sessionId NVARCHAR(50) OUT
    ,@userId INT OUT
    ,@ImplementationID NVARCHAR(50)
    ,@IsUpdateAllowed BIT = 'False'
    ,@language  NVARCHAR(50)=NULL OUT
    ,@Result BIGINT OUT
    ,@ResultMessage NVARCHAR(MAX) OUT
AS
BEGIN
    DECLARE 
         @UserProfileID BIGINT
        ,@IsFirstLoginPending BIT
        ,@IsChangePasswordPending BIT 
        ,@LastLoginOn NVARCHAR(19)
        ,@UserProfileXML XML
        ,@ActivityDetails XML
        ,@AccessRightsXML XML 
        ,@ExpirationTreshold INT = 3600        
        ,@UserIPAddress NVARCHAR(46)
        
    set @sessionId=@currentSessionId
    
	IF (@sessionId IS NOT NULL)
    BEGIN
		EXEC [utUserManagement].[SessionLogin]
			@SessionKey=@sessionId,
			@ExpirationTreshold=@ExpirationTreshold,
			@UserSessionData = N'{}',
			@ActivityDetails =@ActivityDetails,
			@UserProfileID=@UserProfileID,
			@UserProfileXML =@UserProfileXML OUT,
			@AccessRightsXML =@AccessRightsXML OUTPUT,
			@Result =@Result OUTPUT,
			@ResultMessage =@ResultMessage OUTPUT
			SET @userId= @UserProfileXML.value('(/UserProfile/UserProfileID/text())[1]', 'int')
    END
    ELSE IF (@userName IS NOT NULL AND @password IS NOT NULL)
    BEGIN
        EXEC [utUserManagement].[CredentialsLogin]
            @Username =@userName,
            @Password =@password,
            @ImplementationID=@ImplementationID,
            @ActivityDetails = @ActivityDetails,
            @UserProfileID =@UserProfileID OUTPUT,
            @IsFirstLoginPending =@IsFirstLoginPending OUTPUT,
            @IsChangePasswordPending=@IsChangePasswordPending OUTPUT,
            @LastLoginOn =@LastLoginOn OUTPUT,
            @UserProfileXML = @UserProfileXML OUTPUT,
            @AccessRightsXML =@AccessRightsXML OUTPUT,
            @Result =@Result OUTPUT,
            @ResultMessage=@ResultMessage OUTPUT

        SET @userId = @UserProfileXML.value('(/UserProfile/UserProfileID/text())[1]', 'int')

        IF (@Result > 0)
        BEGIN
            SELECT
                @userId = up.UserProfileID,
                @Result = 0
            FROM utUserManagement.tUserCredentials uc
            JOIN utUserManagement.tUserProfileCredentials up ON up.UserCredentialsID = uc.UserCredentialsID
            JOIN utnetCore.tImplementationPorts p ON p.PortID = uc.PortID
            WHERE p.ImplementationID = @ImplementationID
            AND uc.IsSystemCredential = 0
            AND uc.PasswordHash = @password
            AND uc.Username = @userName;

            IF (@userId IS NULL)
            BEGIN
                SET @Result = 2001
                SET @ResultMessage = 'Invalid userName'
            END
        END
    END

    IF(@Result > 0)
        RETURN

    IF(@sessionId IS NULL)
    BEGIN
        EXEC [utUserManagement].[CreateSessionKey]
        @SessionKey =@sessionId OUTPUT
    END 
  
    EXEC [utUserManagement].[SetActiveUserSession]
        @UserProfileID =@userId,
        @ImplementationID =@ImplementationID,
        @UserSessionKey =@sessionId,
        @ExpirationTreshold =@ExpirationTreshold,
        @UserIPAddress =@UserIPAddress,
        @IsUpdateAllowed =@IsUpdateAllowed,
        @UserSessionData = N'{}',
        @Result =@Result OUTPUT,
        @ResultMessage =@ResultMessage OUTPUT

    SELECT
        @language=user1.c.value('LanguageID[1]', 'nvarchar(50)')
    FROM
        @UserProfileXML.nodes('/UserProfile') AS user1(c)
END

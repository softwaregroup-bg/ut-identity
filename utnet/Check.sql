USE [UTNetSystem_3_2]
GO
/****** Object:  StoredProcedure [utIdentity].[Check]    Script Date: 6/12/2015 5:44:05 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
ALTER PROCEDURE [utIdentity].[Check]
     @userName NVARCHAR(50)
    ,@password NVARCHAR(150)
    ,@sessionId NVARCHAR(50) OUT
    ,@userId INT OUT
    ,@ImplementationID NVARCHAR(50)
    ,@SessionData NVARCHAR(MAX)
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
	IF (@sessionId IS NOT NULL)
    BEGIN
		EXEC [utUserManagement].[SessionLogin]
			@SessionKey=@sessionId,
			@ExpirationTreshold=@ExpirationTreshold,
			@ActivityDetails =@ActivityDetails,
			@UserProfileID=@UserProfileID,
			@UserProfileXML =@UserProfileXML OUT,
			@AccessRightsXML =@AccessRightsXML OUTPUT,
			@SessionData=@SessionData OUTPUT,
			@Result =@Result OUTPUT,
			@ResultMessage =@ResultMessage OUTPUT
			SET @userId= @UserProfileXML.value('(/UserProfile/UserProfileID/text())[1]', 'int')
    END
        ELSE
            IF (@userName IS NOT NULL AND @password IS NOT NULL)
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
					SET @userId= @UserProfileXML.value('(/UserProfile/UserProfileID/text())[1]', 'int')
            END
                ELSE
                    IF(@userId  IS NOT NULL)
                    BEGIN
                        EXEC  [utUserManagement].[GetUserProfile]
                            @UserProfileID=@userId,
                            @Username= @userName,
                            @ImplementationID =@ImplementationID,
                            @UserProfileXML =@UserProfileXML OUTPUT,
                            @AccessRightsXML =@AccessRightsXML OUTPUT,
                            @Result =@Result OUTPUT, -- added in 1.1
                            @ResultMessage =@ResultMessage OUTPUT
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
	    @UserSessionData=@SessionData,
	    @ExpirationTreshold =@ExpirationTreshold,
	    @UserIPAddress =@UserIPAddress,
	    @IsUpdateAllowed =@IsUpdateAllowed,
	    @Result =@Result OUTPUT,
	    @ResultMessage =@ResultMessage OUTPUT

    SELECT
		@language=user1.c.value('LanguageID[1]', 'nvarchar(50)')
	 FROM
		@UserProfileXML.nodes('/UserProfile') AS user1(c)
END
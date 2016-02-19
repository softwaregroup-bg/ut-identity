ALTER PROCEDURE [identity].[check]
     @username NVARCHAR(200),
     @password varchar(max),
     @portName NVARCHAR(100),
     @StartTime TIME(0) = NULL,
     @DeviceID NVARCHAR(100) = NULL
AS

SET NOCOUNT ON;

BEGIN TRY
    SELECT
        actorId
    FROM
        [user].hash
    WHERE
        identifier=@username
        AND [value]=@password
END TRY
BEGIN CATCH
   IF @@trancount > 0 ROLLBACK TRANSACTION
   EXEC error_handler_sp
   RETURN 55555
END CATCH
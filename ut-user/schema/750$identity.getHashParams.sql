ALTER PROCEDURE [identity].[getHashParams]
     @username NVARCHAR(50)
AS
    SELECT
        params, algorithm, actorId
    FROM
        [user].hash
    WHERE
        identifier=@username
        AND isEnabled=1
        AND type='password'
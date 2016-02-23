ALTER PROCEDURE [identity].[errorInfoGet] @ErrorMessage [nvarchar](max) out
AS
begin
    set @ErrorMessage = 'Error number: ' + convert(nvarchar(10), ERROR_NUMBER())
       + ', Error severity: ' + convert(nvarchar(10), ERROR_SEVERITY())
       + ', Error state: ' +  convert(nvarchar(10), ERROR_STATE())
       + ', Error procedure: ' + isnull(ERROR_PROCEDURE(), '')
       + ', Error line: ' + convert(nvarchar(10),ERROR_LINE())
       + ', Error Message: ' + ERROR_MESSAGE()
end
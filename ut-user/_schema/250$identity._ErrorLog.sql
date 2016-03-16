CREATE TABLE [identity].[_ErrorLog](
    [Id] [bigint] IDENTITY,
    [ErrorInfo] [nvarchar](max) NOT NULL,
    [Params] [nvarchar](max) NULL,
    [ErrorTimeStamp] [datetime2] NOT NULL CONSTRAINT [DF__ErrorLog_ErrorTimeStamp] DEFAULT (getdate()),
    CONSTRAINT [PK__ErrorLog] PRIMARY KEY CLUSTERED ([Id]) WITH (FILLFACTOR = 80)
)
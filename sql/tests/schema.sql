-- Test schema shaped like the production tables.
CREATE TABLE dbo.Patients (PatientId int PRIMARY KEY);
CREATE TABLE dbo.APILog (
    Id              int IDENTITY PRIMARY KEY,
    Endpoint        nvarchar(200) NOT NULL,
    RequestBody     nvarchar(max) NULL,
    RequestBodyAnsi varchar(max)  NULL,
    ResponseBody    nvarchar(max) NULL,
    StatusCode      int           NOT NULL,
    CreatedAt       datetime2(3)  NOT NULL
);
CREATE TABLE dbo.PT_PatientCards (
    CardId     int PRIMARY KEY,
    PatientId  int NOT NULL REFERENCES dbo.Patients (PatientId),
    CardNumber varchar(19) NULL,
    Cvv        varchar(4)  NULL,
    ExpMonth   tinyint     NULL,
    ExpYear    smallint    NULL
);
GO
CREATE VIEW dbo.vPatientCards AS SELECT CardId, PatientId FROM dbo.PT_PatientCards;
GO
INSERT dbo.Patients VALUES (1), (2);
INSERT dbo.PT_PatientCards VALUES (1, 1, '4111111111111111', '123', 12, 2027), (2, 2, NULL, NULL, NULL, NULL);

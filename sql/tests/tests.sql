SET NOCOUNT ON;
SET XACT_ABORT ON;
GO
-- T1: T-SQL masking matches the shared fixtures character for character (same cases as the C# tests).
IF EXISTS (SELECT 1 FROM dbo.ExpectedRedaction
           WHERE ISNULL(pci_cleanup.RedactCardData(Input), N'') COLLATE Latin1_General_BIN2
                 <> Expected COLLATE Latin1_General_BIN2)
BEGIN
    SELECT Name, Input, pci_cleanup.RedactCardData(Input) AS Got, Expected FROM dbo.ExpectedRedaction
    WHERE ISNULL(pci_cleanup.RedactCardData(Input), N'') COLLATE Latin1_General_BIN2 <> Expected COLLATE Latin1_General_BIN2;
    THROW 50101, 'T1 failed: T-SQL redaction differs from the shared fixtures', 1;
END;
IF pci_cleanup.RedactCardData(NULL) IS NOT NULL THROW 50102, 'T1 failed: NULL must stay NULL', 1;
PRINT 'ok   T1 T-SQL redaction matches all shared fixtures';
GO
-- T2: inventory is read-only and counts exactly the rows that hold card data.
SELECT * INTO #before FROM dbo.APILog;
CREATE TABLE #inv (TableName nvarchar(256), ColumnName sysname NULL, RowsInTable bigint, RowsWithValue bigint, RowsWithCardData bigint NULL);
INSERT #inv EXEC pci_cleanup.Inventory;
DECLARE @expected bigint = (SELECT COUNT(*) FROM dbo.ExpectedRedaction WHERE Input COLLATE Latin1_General_BIN2 <> Expected COLLATE Latin1_General_BIN2);
IF (SELECT RowsWithCardData FROM #inv WHERE ColumnName = N'RequestBody') <> @expected
   OR (SELECT RowsWithCardData FROM #inv WHERE ColumnName = N'RequestBodyAnsi') <> @expected
   OR (SELECT RowsWithCardData FROM #inv WHERE ColumnName = N'ResponseBody') <> 0
    THROW 50201, 'T2 failed: inventory counts are wrong', 1;
IF (SELECT RowsWithValue FROM #inv WHERE TableName = N'dbo.PT_PatientCards' AND ColumnName = N'CardNumber') <> 1
    THROW 50202, 'T2 failed: PT_PatientCards CardNumber count should be 1', 1;
IF EXISTS (SELECT * FROM #before EXCEPT SELECT * FROM dbo.APILog) THROW 50203, 'T2 failed: inventory changed data', 1;
PRINT 'ok   T2 inventory counts card data and changes nothing';
GO
-- T3: dry run changes nothing and writes no audit rows.
EXEC pci_cleanup.MaskApiLog @DryRun = 1;
IF EXISTS (SELECT * FROM #before EXCEPT SELECT * FROM dbo.APILog)
   OR EXISTS (SELECT * FROM dbo.APILog EXCEPT SELECT * FROM #before)
    THROW 50301, 'T3 failed: dry run changed data', 1;
IF EXISTS (SELECT 1 FROM pci_cleanup.MaskAudit) THROW 50302, 'T3 failed: dry run wrote audit rows', 1;
PRINT 'ok   T3 dry run changes nothing';
GO
-- T4: masking (small batches to exercise the loop) gives exactly the expected text; nothing else changes.
EXEC pci_cleanup.MaskApiLog @DryRun = 0, @BatchSize = 3;
IF EXISTS (SELECT 1 FROM dbo.APILog a JOIN dbo.ExpectedRedaction e ON e.Id = a.Id
           WHERE ISNULL(a.RequestBody, N'') COLLATE Latin1_General_BIN2 <> e.Expected COLLATE Latin1_General_BIN2
              OR ISNULL(a.RequestBodyAnsi, '') COLLATE Latin1_General_BIN2 <> CAST(e.Expected AS varchar(max)) COLLATE Latin1_General_BIN2)
    THROW 50401, 'T4 failed: masked text differs from expected', 1;
IF EXISTS (SELECT a.Id, a.Endpoint, a.ResponseBody, a.StatusCode, a.CreatedAt FROM dbo.APILog a
           EXCEPT SELECT b.Id, b.Endpoint, b.ResponseBody, b.StatusCode, b.CreatedAt FROM #before b)
    THROW 50402, 'T4 failed: unrelated columns changed', 1;
IF EXISTS (SELECT a.* FROM dbo.APILog a JOIN #before b ON b.Id = a.Id
           WHERE a.Id NOT IN (SELECT Id FROM dbo.ExpectedRedaction WHERE Input COLLATE Latin1_General_BIN2 <> Expected COLLATE Latin1_General_BIN2)
             AND (ISNULL(a.RequestBody, N'~') COLLATE Latin1_General_BIN2 <> ISNULL(b.RequestBody, N'~') COLLATE Latin1_General_BIN2))
    THROW 50403, 'T4 failed: a row without card data changed', 1;
DECLARE @changed int = (SELECT COUNT(*) FROM dbo.ExpectedRedaction WHERE Input COLLATE Latin1_General_BIN2 <> Expected COLLATE Latin1_General_BIN2);
IF (SELECT COUNT(*) FROM pci_cleanup.MaskAudit) <> 2 * @changed
    THROW 50404, 'T4 failed: audit should have one row per masked row and column', 1;
IF EXISTS (SELECT 1 FROM pci_cleanup.MaskAudit WHERE KeyValue LIKE '%4111%')
    THROW 50405, 'T4 failed: audit must hold keys only, never values', 1;
PRINT 'ok   T4 masking matches expected text and touches nothing else';
GO
-- T5: re-running is a no-op.
DECLARE @audit int = (SELECT COUNT(*) FROM pci_cleanup.MaskAudit);
SELECT * INTO #after FROM dbo.APILog;
EXEC pci_cleanup.MaskApiLog @DryRun = 0;
IF (SELECT COUNT(*) FROM pci_cleanup.MaskAudit) <> @audit OR EXISTS (SELECT * FROM dbo.APILog EXCEPT SELECT * FROM #after)
    THROW 50501, 'T5 failed: second run changed something', 1;
PRINT 'ok   T5 re-run is a no-op';
GO
-- T6: the card table is not dropped while a view still references it.
BEGIN TRY
    EXEC pci_cleanup.RetireCardsTable @Execute = 1;
    THROW 50601, 'T6 failed: drop should have been refused', 1;
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() <> 50003 THROW;
END CATCH;
IF OBJECT_ID(N'dbo.PT_PatientCards', N'U') IS NULL THROW 50602, 'T6 failed: table was dropped despite the dependency', 1;
PRINT 'ok   T6 retire refuses while dbo.vPatientCards depends on the table';
GO
-- T7: report-only mode leaves the table; execute clears and drops it once dependencies are gone.
DROP VIEW dbo.vPatientCards;
EXEC pci_cleanup.RetireCardsTable @Execute = 0;
IF OBJECT_ID(N'dbo.PT_PatientCards', N'U') IS NULL THROW 50701, 'T7 failed: report-only mode dropped the table', 1;
EXEC pci_cleanup.RetireCardsTable @Execute = 1;
IF OBJECT_ID(N'dbo.PT_PatientCards', N'U') IS NOT NULL THROW 50702, 'T7 failed: table still exists', 1;
EXEC pci_cleanup.RetireCardsTable @Execute = 1;  -- running again is harmless
PRINT 'ok   T7 table cleared and dropped; re-run is harmless';
GO
-- T8: the runner scripts and the cleanup script execute as shipped.
:r /tmp/work/sql/01_inventory_readonly.sql
:r /tmp/work/sql/02_mask_apilog.sql
:r /tmp/work/sql/03_retire_pt_patientcards.sql
:r /tmp/work/sql/99_drop_objects.sql
GO
IF OBJECT_ID(N'pci_cleanup.RedactCardData') IS NOT NULL OR OBJECT_ID(N'pci_cleanup.MaskAudit', N'U') IS NULL
    THROW 50801, 'T8 failed: 99 should drop the helpers and keep the audit table', 1;
PRINT 'ok   T8 shipped scripts run; cleanup keeps the audit table';
GO

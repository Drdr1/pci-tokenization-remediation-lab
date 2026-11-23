-- 03: clears and drops the unused PT_PatientCards table.
-- Step 1: run as is (report only): row count and anything still referencing the table.
-- Step 2: after the code change that removes the table from the data model is deployed,
--         set @Execute = 1. It refuses to run while any dependency remains.
EXEC pci_cleanup.RetireCardsTable @CardsTable = N'dbo.PT_PatientCards', @Execute = 0;

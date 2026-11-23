-- 01: READ-ONLY. Counts card data in the API log and shows what PT_PatientCards holds.
-- Run 00_objects.sql first. Changes no data.
EXEC pci_cleanup.Inventory @ApiLogTable = N'dbo.APILog', @CardsTable = N'dbo.PT_PatientCards';

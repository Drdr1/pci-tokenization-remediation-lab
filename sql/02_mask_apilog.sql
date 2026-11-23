-- 02: masks PANs (keeps last 4) and CVV values in every text column of the API log.
-- Step 1: run as is (dry run) and compare the counts with 01.
-- Step 2: after review and a backup, set @DryRun = 0 and run again. Safe to re-run.
EXEC pci_cleanup.MaskApiLog @ApiLogTable = N'dbo.APILog', @DryRun = 1, @BatchSize = 1000;

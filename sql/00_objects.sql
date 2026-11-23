/*
  00_objects.sql - review this file first.

  Creates schema [pci_cleanup] with:
    pci_cleanup.RedactPans(@s)          mask PANs, keep last 4 digits
    pci_cleanup.RedactCvv(@s)           mask CVV values under known key names
    pci_cleanup.RedactCardData(@s)      both of the above
    pci_cleanup.ContainsCardData(@s)    1 if RedactCardData would change @s
    pci_cleanup.Inventory               READ-ONLY counts (APILog and PT_PatientCards)
    pci_cleanup.MaskApiLog              masks APILog text columns in batches (dry run by default)
    pci_cleanup.RetireCardsTable        clears and drops PT_PatientCards (report-only by default)
    pci_cleanup.MaskAudit               table: which row/column was masked and when (no values)

  This script creates objects only; it reads and changes no application data.
  The detection rules match src/PaymentsDemo/Security/CardData.cs exactly
  (both are tested against tests/fixtures/redaction_cases.json):

  PAN: 13-19 digits, optionally split by single spaces or dashes between
  digits, first digit 2-6, Luhn-valid, not touching other digits. All digits
  except the last four become '*'; separators are kept.
  CVV: exactly 3 or 4 digits as the value of cvv, cvv2, cvc, cvc2, cardcode,
  card_code, securitycode or security_code (any case), in JSON, form or XML
  form. The value becomes '***'.

  Digits are tested by code point (48-57), never with LIKE '[0-9]', because
  under some collations that range also matches characters such as '²'.
*/
SET NOCOUNT ON;
GO
IF SCHEMA_ID(N'pci_cleanup') IS NULL EXEC (N'CREATE SCHEMA pci_cleanup AUTHORIZATION dbo');
GO

CREATE OR ALTER FUNCTION pci_cleanup.RedactPans (@s nvarchar(max))
RETURNS nvarchar(max)
AS
BEGIN
    IF @s IS NULL RETURN NULL;
    DECLARE @n int = DATALENGTH(@s) / 2;
    DECLARE @i int = 1, @j int, @k int, @u int, @prev int, @next int;
    DECLARE @d varchar(64), @cnt int, @sum int, @dbl bit, @dig int, @masked int;

    WHILE @i <= @n
    BEGIN
        SET @u = UNICODE(SUBSTRING(@s, @i, 1));
        SET @prev = CASE WHEN @i > 1 THEN UNICODE(SUBSTRING(@s, @i - 1, 1)) ELSE 0 END;
        IF @u NOT BETWEEN 48 AND 57 OR @prev BETWEEN 48 AND 57
        BEGIN
            SET @i += 1;
            CONTINUE;
        END;

        -- Collect a run of digits with single separators between digits.
        SET @j = @i;
        SET @d = '';
        WHILE @j <= @n
        BEGIN
            SET @u = UNICODE(SUBSTRING(@s, @j, 1));
            IF @u BETWEEN 48 AND 57
            BEGIN
                IF LEN(@d) < 60 SET @d += CHAR(@u);
                ELSE SET @d += '0';
                SET @j += 1;
            END
            ELSE
            BEGIN
                SET @next = CASE WHEN @j + 1 <= @n THEN UNICODE(SUBSTRING(@s, @j + 1, 1)) ELSE 0 END;
                SET @prev = UNICODE(SUBSTRING(@s, @j - 1, 1));
                IF @u IN (32, 45) AND @next BETWEEN 48 AND 57 AND @j > @i AND @prev BETWEEN 48 AND 57
                    SET @j += 1;
                ELSE
                    BREAK;
            END;
        END;

        SET @cnt = LEN(@d);
        IF @cnt BETWEEN 13 AND 19 AND LEFT(@d, 1) BETWEEN '2' AND '6'
        BEGIN
            -- Luhn
            SET @sum = 0; SET @dbl = 0; SET @k = @cnt;
            WHILE @k >= 1
            BEGIN
                SET @dig = ASCII(SUBSTRING(@d, @k, 1)) - 48;
                IF @dbl = 1 BEGIN SET @dig *= 2; IF @dig > 9 SET @dig -= 9; END;
                SET @sum += @dig;
                SET @dbl = 1 - @dbl;
                SET @k -= 1;
            END;
            IF @sum % 10 = 0
            BEGIN
                SET @k = @i; SET @masked = 0;
                WHILE @k < @j AND @masked < @cnt - 4
                BEGIN
                    IF UNICODE(SUBSTRING(@s, @k, 1)) BETWEEN 48 AND 57
                    BEGIN
                        SET @s = STUFF(@s, @k, 1, N'*');
                        SET @masked += 1;
                    END;
                    SET @k += 1;
                END;
            END;
        END;
        SET @i = @j;
    END;
    RETURN @s;
END;
GO

-- End position (exclusive) of a run of exactly 3 or 4 digits starting at @start, or 0.
CREATE OR ALTER FUNCTION pci_cleanup.CvvEnd (@s nvarchar(max), @start int)
RETURNS int
AS
BEGIN
    DECLARE @n int = DATALENGTH(@s) / 2, @e int = @start;
    WHILE @e <= @n AND UNICODE(SUBSTRING(@s, @e, 1)) BETWEEN 48 AND 57 AND @e - @start < 5
        SET @e += 1;
    RETURN CASE WHEN @e - @start IN (3, 4) THEN @e ELSE 0 END;
END;
GO

CREATE OR ALTER FUNCTION pci_cleanup.RedactCvv (@s nvarchar(max))
RETURNS nvarchar(max)
AS
BEGIN
    IF @s IS NULL RETURN NULL;
    DECLARE @keys TABLE (ord int PRIMARY KEY, k nvarchar(20));
    INSERT @keys VALUES (1, N'cvv'), (2, N'cvv2'), (3, N'cvc'), (4, N'cvc2'), (5, N'cardcode'),
                        (6, N'card_code'), (7, N'securitycode'), (8, N'security_code');

    DECLARE @ord int = 1, @key nvarchar(20), @marker nvarchar(30);
    DECLARE @n int, @from int, @at int, @j int, @e int, @q bit, @ok bit, @c int;

    WHILE @ord <= 8
    BEGIN
        SELECT @key = k FROM @keys WHERE ord = @ord;

        -- JSON: "key" : "123"  or  "key":123
        SET @marker = N'"' + @key + N'"'; SET @from = 1;
        WHILE 1 = 1
        BEGIN
            SET @n = DATALENGTH(@s) / 2;
            SET @at = CHARINDEX(@marker, LOWER(@s) COLLATE Latin1_General_BIN2, @from);
            IF @at = 0 BREAK;
            SET @j = @at + LEN(@marker);
            WHILE @j <= @n AND SUBSTRING(@s, @j, 1) = N' ' SET @j += 1;
            IF @j > @n OR SUBSTRING(@s, @j, 1) <> N':' BEGIN SET @from = @at + 1; CONTINUE; END;
            SET @j += 1;
            WHILE @j <= @n AND SUBSTRING(@s, @j, 1) = N' ' SET @j += 1;
            SET @q = CASE WHEN @j <= @n AND SUBSTRING(@s, @j, 1) = N'"' THEN 1 ELSE 0 END;
            IF @q = 1 SET @j += 1;
            SET @e = pci_cleanup.CvvEnd(@s, @j);
            SET @c = CASE WHEN @e > 0 AND @e <= @n THEN UNICODE(SUBSTRING(@s, @e, 1)) ELSE -1 END;
            SET @ok = CASE
                WHEN @e = 0 THEN 0
                WHEN @q = 1 THEN CASE WHEN @c = 34 THEN 1 ELSE 0 END
                WHEN @e > @n OR @c NOT BETWEEN 48 AND 57 THEN 1 ELSE 0 END;
            IF @ok = 1 BEGIN SET @s = STUFF(@s, @j, @e - @j, N'***'); SET @from = @j + 3; END
            ELSE SET @from = @at + 1;
        END;

        -- Form / query: key=123 at the start or after & ? space tab CR LF
        SET @marker = @key + N'='; SET @from = 1;
        WHILE 1 = 1
        BEGIN
            SET @n = DATALENGTH(@s) / 2;
            SET @at = CHARINDEX(@marker, LOWER(@s) COLLATE Latin1_General_BIN2, @from);
            IF @at = 0 BREAK;
            SET @c = CASE WHEN @at > 1 THEN UNICODE(SUBSTRING(@s, @at - 1, 1)) ELSE -1 END;
            SET @j = @at + LEN(@marker);
            SET @e = pci_cleanup.CvvEnd(@s, @j);
            IF (@c = -1 OR @c IN (38, 63, 32, 10, 13, 9)) AND @e > 0
               AND (@e > @n OR UNICODE(SUBSTRING(@s, @e, 1)) NOT BETWEEN 48 AND 57)
            BEGIN
                SET @s = STUFF(@s, @j, @e - @j, N'***'); SET @from = @j + 3;
            END
            ELSE SET @from = @at + 1;
        END;

        -- XML: <key>123</
        SET @marker = N'<' + @key + N'>'; SET @from = 1;
        WHILE 1 = 1
        BEGIN
            SET @n = DATALENGTH(@s) / 2;
            SET @at = CHARINDEX(@marker, LOWER(@s) COLLATE Latin1_General_BIN2, @from);
            IF @at = 0 BREAK;
            SET @j = @at + LEN(@marker);
            SET @e = pci_cleanup.CvvEnd(@s, @j);
            IF @e > 0 AND SUBSTRING(@s, @e, 2) COLLATE Latin1_General_BIN2 = N'</'
            BEGIN
                SET @s = STUFF(@s, @j, @e - @j, N'***'); SET @from = @j + 3;
            END
            ELSE SET @from = @at + 1;
        END;

        SET @ord += 1;
    END;
    RETURN @s;
END;
GO

CREATE OR ALTER FUNCTION pci_cleanup.RedactCardData (@s nvarchar(max))
RETURNS nvarchar(max)
AS
BEGIN
    RETURN pci_cleanup.RedactCvv(pci_cleanup.RedactPans(@s));
END;
GO

CREATE OR ALTER FUNCTION pci_cleanup.ContainsCardData (@s nvarchar(max))
RETURNS bit
AS
BEGIN
    IF @s IS NULL RETURN 0;
    RETURN CASE WHEN pci_cleanup.RedactCardData(@s) COLLATE Latin1_General_BIN2 = @s COLLATE Latin1_General_BIN2
                THEN 0 ELSE 1 END;
END;
GO

IF OBJECT_ID(N'pci_cleanup.MaskAudit', N'U') IS NULL
    CREATE TABLE pci_cleanup.MaskAudit (
        AuditId     bigint IDENTITY PRIMARY KEY,
        TableName   sysname       NOT NULL,
        ColumnName  sysname       NOT NULL,
        KeyValue    nvarchar(100) NOT NULL,
        MaskedAtUtc datetime2(0)  NOT NULL DEFAULT SYSUTCDATETIME()
    );
GO

/* Text columns of a table that can hold card data: (n)char, (n)varchar, (n)text. */
CREATE OR ALTER FUNCTION pci_cleanup.TextColumns (@object_id int)
RETURNS TABLE
AS
RETURN
    SELECT c.name AS ColumnName, c.column_id
    FROM sys.columns c
    JOIN sys.types t ON t.user_type_id = c.user_type_id
    WHERE c.object_id = @object_id
      AND t.name IN (N'char', N'varchar', N'nchar', N'nvarchar', N'text', N'ntext')
      AND (c.max_length = -1 OR c.max_length >= 3 OR t.name IN (N'text', N'ntext'))
      AND c.is_computed = 0;
GO

/*
  READ-ONLY. Counts rows that contain card data, per text column of the API log,
  and shows what PT_PatientCards holds. Changes nothing.
*/
CREATE OR ALTER PROCEDURE pci_cleanup.Inventory
    @ApiLogTable nvarchar(256) = N'dbo.APILog',
    @CardsTable  nvarchar(256) = N'dbo.PT_PatientCards'
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @log_id int = OBJECT_ID(@ApiLogTable, N'U'), @cards_id int = OBJECT_ID(@CardsTable, N'U');
    DECLARE @sql nvarchar(max), @col sysname, @rows bigint, @hits bigint;
    DECLARE @log_q nvarchar(300) = QUOTENAME(OBJECT_SCHEMA_NAME(@log_id)) + N'.' + QUOTENAME(OBJECT_NAME(@log_id));
    DECLARE @cards_q nvarchar(300) = QUOTENAME(OBJECT_SCHEMA_NAME(@cards_id)) + N'.' + QUOTENAME(OBJECT_NAME(@cards_id));
    DECLARE @result TABLE (TableName nvarchar(256), ColumnName sysname NULL, RowsInTable bigint,
                           RowsWithValue bigint, RowsWithCardData bigint NULL);

    IF @log_id IS NOT NULL
    BEGIN
        DECLARE cols CURSOR LOCAL FAST_FORWARD FOR
            SELECT ColumnName FROM pci_cleanup.TextColumns(@log_id) ORDER BY column_id;
        OPEN cols;
        FETCH NEXT FROM cols INTO @col;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'SELECT @rows = COUNT_BIG(*), @hits = SUM(CASE WHEN ' + QUOTENAME(@col) +
                N' IS NOT NULL AND (' + QUOTENAME(@col) + N' LIKE N''%[0-9][0-9][0-9]%'' OR ' + QUOTENAME(@col) +
                N' LIKE N''%[0-9][ -][0-9]%'') AND pci_cleanup.ContainsCardData(CAST(' + QUOTENAME(@col) +
                N' AS nvarchar(max))) = 1 THEN 1 ELSE 0 END) FROM ' + @log_q + N';';
            EXEC sp_executesql @sql, N'@rows bigint OUTPUT, @hits bigint OUTPUT', @rows OUTPUT, @hits OUTPUT;
            INSERT @result VALUES (@ApiLogTable, @col, @rows, NULL, ISNULL(@hits, 0));
            FETCH NEXT FROM cols INTO @col;
        END;
        CLOSE cols; DEALLOCATE cols;
    END
    ELSE INSERT @result VALUES (@ApiLogTable + N' (not found)', NULL, 0, NULL, NULL);

    IF @cards_id IS NOT NULL
    BEGIN
        DECLARE ccols CURSOR LOCAL FAST_FORWARD FOR
            SELECT name FROM sys.columns WHERE object_id = @cards_id ORDER BY column_id;
        OPEN ccols;
        FETCH NEXT FROM ccols INTO @col;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'SELECT @rows = COUNT_BIG(*), @hits = COUNT_BIG(' + QUOTENAME(@col) + N') FROM ' +
                       @cards_q + N';';
            EXEC sp_executesql @sql, N'@rows bigint OUTPUT, @hits bigint OUTPUT', @rows OUTPUT, @hits OUTPUT;
            INSERT @result VALUES (@CardsTable, @col, @rows, @hits, NULL);
            FETCH NEXT FROM ccols INTO @col;
        END;
        CLOSE ccols; DEALLOCATE ccols;
    END
    ELSE INSERT @result VALUES (@CardsTable + N' (not found)', NULL, 0, NULL, NULL);

    SELECT TableName, ColumnName, RowsInTable, RowsWithValue, RowsWithCardData FROM @result;
END;
GO

/*
  Masks card data in every text column of the API log, in batches, one
  transaction per batch. Only the matched PAN/CVV characters change; every
  other character, column and row is left as it was. Rows already masked no
  longer match, so the procedure can be stopped and re-run safely.
  @DryRun = 1 (default) only reports what would change.
*/
CREATE OR ALTER PROCEDURE pci_cleanup.MaskApiLog
    @ApiLogTable nvarchar(256) = N'dbo.APILog',
    @DryRun      bit = 1,
    @BatchSize   int = 1000
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @log_id int = OBJECT_ID(@ApiLogTable, N'U');
    IF @log_id IS NULL THROW 50001, 'API log table not found.', 1;
    DECLARE @log_q nvarchar(300) = QUOTENAME(OBJECT_SCHEMA_NAME(@log_id)) + N'.' + QUOTENAME(OBJECT_NAME(@log_id));

    DECLARE @pk sysname, @pk_count int;
    SELECT @pk_count = COUNT(*), @pk = MAX(c.name)
    FROM sys.indexes i
    JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
    JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
    WHERE i.object_id = @log_id AND i.is_primary_key = 1;
    IF @pk_count <> 1 THROW 50002, 'The API log table needs a single-column primary key.', 1;

    DECLARE @col sysname, @sql nvarchar(max), @match nvarchar(max), @batch int, @total bigint;
    DECLARE @summary TABLE (ColumnName sysname, RowsMasked bigint);

    DECLARE cols CURSOR LOCAL FAST_FORWARD FOR
        SELECT ColumnName FROM pci_cleanup.TextColumns(@log_id) WHERE ColumnName <> @pk ORDER BY column_id;
    OPEN cols;
    FETCH NEXT FROM cols INTO @col;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @match = QUOTENAME(@col) + N' IS NOT NULL AND (' + QUOTENAME(@col) + N' LIKE N''%[0-9][0-9][0-9]%'' OR ' +
                     QUOTENAME(@col) + N' LIKE N''%[0-9][ -][0-9]%'') AND pci_cleanup.ContainsCardData(CAST(' +
                     QUOTENAME(@col) + N' AS nvarchar(max))) = 1';
        SET @total = 0;
        IF @DryRun = 1
        BEGIN
            SET @sql = N'SELECT @total = COUNT_BIG(*) FROM ' + @log_q + N' WHERE ' + @match + N';';
            EXEC sp_executesql @sql, N'@total bigint OUTPUT', @total OUTPUT;
        END
        ELSE
        BEGIN
            SET @sql = N'
                DECLARE @keys TABLE (k sql_variant PRIMARY KEY);
                BEGIN TRAN;
                INSERT @keys SELECT TOP (@BatchSize) ' + QUOTENAME(@pk) + N' FROM ' + @log_q +
                    N' WITH (UPDLOCK, READPAST) WHERE ' + @match + N' ORDER BY ' + QUOTENAME(@pk) + N';
                UPDATE t SET ' + QUOTENAME(@col) + N' = pci_cleanup.RedactCardData(CAST(t.' + QUOTENAME(@col) +
                    N' AS nvarchar(max)))
                FROM ' + @log_q + N' t JOIN @keys k ON k.k = t.' + QUOTENAME(@pk) + N';
                SET @batch = @@ROWCOUNT;
                INSERT pci_cleanup.MaskAudit (TableName, ColumnName, KeyValue)
                SELECT @table, @column, CONVERT(nvarchar(100), k) FROM @keys;
                COMMIT;';
            SET @batch = 1;
            WHILE @batch > 0
            BEGIN
                EXEC sp_executesql @sql,
                    N'@BatchSize int, @table nvarchar(256), @column sysname, @batch int OUTPUT',
                    @BatchSize, @ApiLogTable, @col, @batch OUTPUT;
                SET @total += @batch;
            END;
        END;
        INSERT @summary VALUES (@col, @total);
        FETCH NEXT FROM cols INTO @col;
    END;
    CLOSE cols; DEALLOCATE cols;

    SELECT @ApiLogTable AS TableName, ColumnName,
           RowsMasked AS RowsAffected,
           CASE WHEN @DryRun = 1 THEN 'dry run: nothing changed' ELSE 'masked' END AS Mode
    FROM @summary;
END;
GO

/*
  Clears and drops the unused card table. @Execute = 0 (default) only reports.
  Refuses to run if any foreign key, view, procedure, function or trigger
  still references the table. Note: dropping the table does not remove old
  copies of its data from backups or the transaction log; see README.
*/
CREATE OR ALTER PROCEDURE pci_cleanup.RetireCardsTable
    @CardsTable nvarchar(256) = N'dbo.PT_PatientCards',
    @Execute    bit = 0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @id int = OBJECT_ID(@CardsTable, N'U');
    IF @id IS NULL
    BEGIN
        SELECT @CardsTable AS TableName, 'not found: nothing to do' AS Result;
        RETURN;
    END;

    DECLARE @deps TABLE (Dependency nvarchar(512));
    INSERT @deps
    SELECT N'foreign key ' + fk.name + N' on ' + OBJECT_SCHEMA_NAME(fk.parent_object_id) + N'.' +
           OBJECT_NAME(fk.parent_object_id)
    FROM sys.foreign_keys fk
    WHERE fk.referenced_object_id = @id AND fk.parent_object_id <> @id;
    INSERT @deps
    SELECT DISTINCT o.type_desc + N' ' + OBJECT_SCHEMA_NAME(d.referencing_id) + N'.' + OBJECT_NAME(d.referencing_id)
    FROM sys.sql_expression_dependencies d
    JOIN sys.objects o ON o.object_id = d.referencing_id
    WHERE d.referenced_id = @id AND d.referencing_id <> @id;

    DECLARE @q nvarchar(300) = QUOTENAME(OBJECT_SCHEMA_NAME(@id)) + N'.' + QUOTENAME(OBJECT_NAME(@id));
    DECLARE @rows bigint, @sql nvarchar(max) = N'SELECT @rows = COUNT_BIG(*) FROM ' + @q + N';';
    EXEC sp_executesql @sql, N'@rows bigint OUTPUT', @rows OUTPUT;

    SELECT @CardsTable AS TableName, @rows AS RowsInTable,
           (SELECT COUNT(*) FROM @deps) AS BlockingDependencies;
    SELECT Dependency FROM @deps;

    IF @Execute = 0 RETURN;
    IF EXISTS (SELECT 1 FROM @deps)
        THROW 50003, 'PT_PatientCards is still referenced; remove the dependencies listed above first.', 1;

    BEGIN TRAN;
        SET @sql = N'DELETE FROM ' + @q + N'; DROP TABLE ' + @q + N';';
        EXEC (@sql);
    COMMIT;
    SELECT @CardsTable AS TableName, @rows AS RowsCleared, 'dropped' AS Result;
END;
GO

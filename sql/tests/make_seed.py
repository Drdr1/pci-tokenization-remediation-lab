"""Writes seed SQL from tests/fixtures/redaction_cases.json (the same cases the C# tests use)."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[2]
cases = json.loads((root / "tests/fixtures/redaction_cases.json").read_text())


def q(s):
    return "N'" + s.replace("'", "''") + "'"


out = ["CREATE TABLE dbo.ExpectedRedaction (Id int PRIMARY KEY, Name nvarchar(100), Input nvarchar(max), Expected nvarchar(max));"]
for i, c in enumerate(cases, start=1):
    out.append(
        "SET IDENTITY_INSERT dbo.APILog ON; "
        f"INSERT dbo.APILog (Id, Endpoint, RequestBody, RequestBodyAnsi, ResponseBody, StatusCode, CreatedAt) VALUES "
        f"({i}, N'/api/case/{c['name']}', {q(c['input'])}, {q(c['input'])}, "
        f"N'{{\"status\":\"ok\",\"ref\":\"A-100200300\",\"case\":{i}}}', 200, '2026-11-23T10:{i:02d}:00'); "
        "SET IDENTITY_INSERT dbo.APILog OFF;"
    )
    out.append(f"INSERT dbo.ExpectedRedaction VALUES ({i}, {q(c['name'])}, {q(c['input'])}, {q(c['expected'])});")
# Rows with no card data at all, and NULLs, must never change.
out.append("INSERT dbo.APILog (Endpoint, RequestBody, RequestBodyAnsi, ResponseBody, StatusCode, CreatedAt) "
           "SELECT N'/api/health', NULL, NULL, N'ok', 200, '2026-11-23T11:00:00' FROM (VALUES (1),(2),(3)) v(x);")
sys.stdout.write("\n".join(out) + "\nGO\n")

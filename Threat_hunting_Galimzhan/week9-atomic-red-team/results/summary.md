# Atomic test detection results (auto-generated)

| atomic_id   | name                                    | attack    | detected   | by_rule   |
|:------------|:----------------------------------------|:----------|:-----------|:----------|
| T1059.003   | Create and Execute Batch Script         | T1059.003 | NO         | -         |
| T1059.001   | Mimikatz-style encoded PowerShell       | T1059.001 | YES        | D2        |
| T1204.002   | OSTap Style Macro Execution (maldoc)    | T1204.002 | YES        | D1        |
| T1003.001   | Dump LSASS.exe Memory using ProcDump    | T1003.001 | YES        | D3        |
| T1003.001   | Dump LSASS.exe Memory using comsvcs.dll | T1003.001 | YES        | D3        |

**Detected 3 of 4 techniques** with my CAR analytics (Week 7) + one new LSASS rule.

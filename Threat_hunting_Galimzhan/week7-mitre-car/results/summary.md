# CAR analytics results (auto-generated)

## Scorecard

| host   | chain                                    | CAR-2013-02-003   | CAR-2014-04-003   |
|:-------|:-----------------------------------------|:------------------|:------------------|
| WKS-07 | outlook.exe -> cmd.exe -> powershell.exe | detected          | detected          |
| WKS-19 | winword.exe -> cmd.exe -> powershell.exe | detected          | detected          |

## Metrics

| analytic                   | attack    |   hits |   true_positives |   false_positives |
|:---------------------------|:----------|-------:|-----------------:|------------------:|
| CAR-2013-02-003            | T1059.003 |      2 |                2 |                 0 |
| CAR-2014-04-003 v1 (raw)   | T1059.001 |    161 |                2 |                23 |
| CAR-2014-04-003 v2 (tuned) | T1059.001 |      2 |                2 |                 0 |

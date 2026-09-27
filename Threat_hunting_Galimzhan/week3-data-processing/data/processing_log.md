# Processing log

- Input rows: **204**
- Invalid hostnames dropped: **0** []
- Duplicates merged after normalization (e.g. www.x = x): **7**
- Filtered out: **2**
  - `usps.postkz.us`: keyword false positive: USPS lure, 'postkz' is coincidental
  - `kazpost.kz`: allowlist: legitimate brand domain
- Enrichment available: VirusTotal=0 rows, Shodan=0 rows
- Output indicators: **195**  (URLs with path: 117)
- Confidence: {'low': 166, 'medium': 29}

## Correlation clusters (same kit signature)

| Cluster | Kit signature | Size | Members |
|---|---|---|---|
| C01-kit | `/m/sing/*` | 5 | appleid.com.kz, appleoficial.com.kz, idapple.com.kz, miaccount.com.kz, soporteapple.com.kz |
| C02-kit | `/la/*` | 2 | applesoporte.com.kz, supportapple.com.kz |
| C03-kit | `/acessomob/loginautentica.php` | 2 | armelincontabilidade-0038853.jcloud.kz, live-mail-microsoft.jcloud.kz |
| C04-kit | `/wp-includes/sodium_compat/src/core` | 2 | celinnaya.kz, joint.kz |
| C05-kit | `/m/*` | 2 | icloud.com.kz, isupport.com.kz |
| C06-kit | `/acessodes/login/logininicial.php` | 2 | loginlivemailoffice365brcombr-newviws342324.jcloud.kz, mail-contasistema-suport.jcloud.kz |

## Platform / brand-family groups

- `P-jcloud.kz`: 21 indicators
- `P-mylp.kz`: 16 indicators
- `F-opensea`: 8 indicators

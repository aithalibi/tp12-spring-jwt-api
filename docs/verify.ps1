# Script de verification de l'API JWT (TP12)
$b = 'http://localhost:8080'
function Ligne($t) { Write-Output ""; Write-Output "================================================================"; Write-Output "  $t"; Write-Output "================================================================" }
$tmp = Join-Path $env:TEMP 'tp12'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
function Json($nom, $contenu) {
    $p = Join-Path $tmp "$nom.json"
    [System.IO.File]::WriteAllText($p, $contenu, (New-Object System.Text.UTF8Encoding($false)))
    return "@$p"
}

$bodyAdmin = Json 'admin-ok' '{"username":"admin","password":"1234"}'
$bodyUser  = Json 'user-ok'  '{"username":"user","password":"1111"}'
$bodyBad   = Json 'admin-ko' '{"username":"admin","password":"0000"}'

Ligne '1. Endpoint public /api/public/info (sans token)'
curl.exe -s -i "$b/api/public/info" | Select-Object -First 1
curl.exe -s "$b/api/public/info"
Write-Output ''

Ligne '2. POST /api/auth/login avec admin / 1234'
curl.exe -s -i -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyAdmin | Select-Object -First 1
$ja = curl.exe -s -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyAdmin
Write-Output $ja
$tokA = ($ja | ConvertFrom-Json).token

Ligne '3. POST /api/auth/login avec user / 1111'
curl.exe -s -i -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyUser | Select-Object -First 1
$ju = curl.exe -s -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyUser
Write-Output $ju
$tokU = ($ju | ConvertFrom-Json).token

Ligne '4. POST /api/auth/login avec un mauvais mot de passe (admin / 0000)'
curl.exe -s -i -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyBad | Select-Object -First 1
curl.exe -s -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyBad
Write-Output ''

Ligne '5. GET /api/user/profile sans token'
curl.exe -s -i "$b/api/user/profile" | Select-Object -First 1

Ligne '6. GET /api/user/profile avec le token de user'
curl.exe -s -i -H "Authorization: Bearer $tokU" "$b/api/user/profile" | Select-Object -First 1
curl.exe -s -H "Authorization: Bearer $tokU" "$b/api/user/profile"
Write-Output ''

Ligne '7. GET /api/admin/dashboard avec le token de user (doit etre 403)'
curl.exe -s -i -H "Authorization: Bearer $tokU" "$b/api/admin/dashboard" | Select-Object -First 1

Ligne '8. GET /api/admin/dashboard avec le token de admin'
curl.exe -s -i -H "Authorization: Bearer $tokA" "$b/api/admin/dashboard" | Select-Object -First 1
curl.exe -s -H "Authorization: Bearer $tokA" "$b/api/admin/dashboard"
Write-Output ''

Ligne '9. GET /api/user/profile avec le token de admin (ADMIN herite de USER)'
curl.exe -s -i -H "Authorization: Bearer $tokA" "$b/api/user/profile" | Select-Object -First 1

Ligne '10. GET /api/user/profile avec un token invalide'
curl.exe -s -i -H 'Authorization: Bearer xxx.yyy.zzz' "$b/api/user/profile" | Select-Object -First 1

Ligne '11. GET /api/user/profile avec un token signe par une autre cle (falsification)'
$faux = ($tokU -split '\.')[0..1] -join '.'
$faux = "$faux.ZmF1c2NlLXNpZ25hdHVyZQ"
curl.exe -s -i -H "Authorization: Bearer $faux" "$b/api/user/profile" | Select-Object -First 1

Ligne '12. Contenu decode du token de user (header / payload)'
$parts = $tokU -split '\.'
function B64($s) { $s = $s.Replace('-', '+').Replace('_', '/'); while ($s.Length % 4) { $s += '=' }; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
Write-Output ('HEADER  : ' + (B64 $parts[0]))
Write-Output ('PAYLOAD : ' + (B64 $parts[1]))
Write-Output ('SIGNATURE (base64url) : ' + $parts[2])

Ligne '13. Contenu decode du token de admin'
$pa = $tokA -split '\.'
Write-Output ('HEADER  : ' + (B64 $pa[0]))
Write-Output ('PAYLOAD : ' + (B64 $pa[1]))

Ligne '14. Pas de session : aucun cookie de session renvoye par le serveur'
$resp = curl.exe -s -D - -o NUL -X POST "$b/api/auth/login" -H 'Content-Type: application/json' --data-binary $bodyUser
$resp | Select-String -Pattern 'Set-Cookie|HTTP/' | ForEach-Object { $_.Line }
Write-Output '(aucune ligne Set-Cookie ci-dessus = API bien STATELESS)'

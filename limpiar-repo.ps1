# limpiar-repo.ps1 - revisa que no se suban archivos que no deben subirse (Hydra Firewall)
# Uso (desde la raiz del repo):
#   .\limpiar-repo.ps1            -> solo muestra lo que encuentra (no cambia nada)
#   .\limpiar-repo.ps1 -Apply     -> actualiza .gitignore y saca del indice lo que no debe estar
# No borra archivos de tu disco: solo deja de seguirlos con git.
param([switch]$Apply)
$ErrorActionPreference = "Continue"

function Say($msg, $color = "Gray") { Write-Host $msg -ForegroundColor $color }

# 1) Seguridad: estamos en el repo correcto?
$top = git rev-parse --show-toplevel 2>$null
if (-not $top) { Say "ERROR: esta carpeta no es un repositorio git." Red; exit 1 }
$top = (Resolve-Path $top).Path
if ((Get-Location).Path -ne $top) { Say "ERROR: ejecutalo desde la raiz del repo: $top" Red; exit 1 }
$remote = git remote get-url origin 2>$null
if ($remote -notmatch 'hydraroot/Hydra_Firewall') {
    Say "ERROR: el remoto origin no es hydraroot/Hydra_Firewall ($remote). No hago nada." Red
    exit 1
}
Say "Repo: $top" Cyan
if ($Apply) { Say "Modo: APLICAR cambios" Yellow } else { Say "Modo: solo revisar (usa -Apply para aplicar)" Yellow }

# 2) .gitignore
$needed = @(
 'local.properties','*.jks','*.keystore','*.pem','!app/src/main/res/raw/*.pem','.gradle/','build/','app/build/',
 '.idea/','*.iml','captures/','.externalNativeBuild/','.cxx/','secrets/',
 '*.p12','*.pfx','*.pk8','*.key','keystore.properties','.env','.env.*',
 '*.apk','*.aab','*.ap_','*.hprof','__pycache__/','*.pyc','.venv/','venv/',
 '.vscode/','.kotlin/','*.log','.DS_Store','Thumbs.db'
)
$cur = @()
if (Test-Path ".gitignore") { $cur = Get-Content ".gitignore" }
$missing = @($needed | Where-Object { $cur -notcontains $_ })
if ($missing.Count -gt 0) {
    Say "`n.gitignore: faltan $($missing.Count) lineas:" Yellow
    $missing | ForEach-Object { Say "   $_" }
    if ($Apply) {
        $block = @("", "# agregado por limpiar-repo.ps1") + $missing
        Add-Content -Path ".gitignore" -Value $block -Encoding ASCII
        Say "   -> agregadas a .gitignore" Green
    }
} else {
    Say "`n.gitignore: completo." Green
}

# 3) Archivos ya seguidos por git que no deberian estarlo
$rx = '(?i)(\.(jks|keystore|p12|pfx|pk8|key|aab|apk|ap_|hprof|log|pyc|iml)$)|((^|/)(local\.properties|keystore\.properties|\.env[^/]*|Thumbs\.db|\.DS_Store)$)|((^|/)(secrets|build|\.gradle|\.idea|\.kotlin|captures|__pycache__|\.vscode|\.cxx)/)'
$tracked = @(git -c core.quotepath=off ls-files)
$bad = @($tracked | Where-Object { $_ -match $rx })
$bad += @($tracked | Where-Object { $_ -match '(?i)\.pem$' -and $_ -notmatch '^app/src/main/res/raw/' })
$bad = @($bad | Sort-Object -Unique)
if ($bad.Count -gt 0) {
    Say "`nSeguidos por git y no deberian estarlo ($($bad.Count)):" Red
    $bad | ForEach-Object { Say "   $_" }
    if ($Apply) {
        foreach ($f in $bad) { git rm --cached -r --quiet -- "$f" }
        Say "   -> quitados del indice (siguen en tu disco). Falta hacer commit." Green
    }
} else {
    Say "Archivos seguidos: ninguno prohibido." Green
}

# 4) Buscar secretos dentro de archivos de texto (no muestra el valor, solo archivo y linea)
$textExt = '(?i)\.(kt|kts|java|xml|json|properties|yml|yaml|md|txt|py|sh|ps1|gradle|toml|pro|yar|cfg)$'
$all = @($tracked) + @(git -c core.quotepath=off ls-files -o --exclude-standard)
$all = @($all | Where-Object { $_ -match $textExt -and $_ -notmatch '(?i)\.example$' -and (Test-Path $_) })
$pat = '(?i)BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|(storePassword|keyPassword|HYDRA_KEYSTORE_PASSWORD|HYDRA_KEY_PASSWORD|ABUSECH_AUTH_KEY|HYDRA_THREAT_SIGNING_KEY)\s*[=:]\s*["'']?[A-Za-z0-9+/_\-]{6,}'
$hits = @()
foreach ($f in $all) {
    if ((Get-Item -LiteralPath $f).Length -gt 2MB) { continue }
    $m = Select-String -LiteralPath $f -Pattern $pat -ErrorAction SilentlyContinue
    foreach ($x in $m) { $hits += "${f}:$($x.LineNumber)" }
}
if ($hits.Count -gt 0) {
    Say "`nPosibles secretos (revisalos a mano, puede haber falsos positivos):" Red
    $hits | ForEach-Object { Say "   $_" }
} else {
    Say "Secretos en archivos de texto: ninguno detectado." Green
}

# 5) Archivos grandes
$big = @($tracked | Where-Object { (Test-Path $_) -and ((Get-Item $_).Length -gt 5MB) })
if ($big.Count -gt 0) {
    Say "`nArchivos de mas de 5 MB seguidos por git:" Yellow
    $big | ForEach-Object { Say ("   {0} ({1:N1} MB)" -f $_, ((Get-Item $_).Length / 1MB)) }
}

# 6) Historial: estuvo alguna vez algo prohibido?
$hist = @(git -c core.quotepath=off log --all --name-only --pretty=format: | Where-Object { $_ } | Sort-Object -Unique)
$histBad = @($hist | Where-Object { $_ -match $rx -or ($_ -match '(?i)\.pem$' -and $_ -notmatch '^app/src/main/res/raw/') })
if ($histBad.Count -gt 0) {
    Say "`nOJO: estos archivos estuvieron en el HISTORIAL de git:" Red
    $histBad | ForEach-Object { Say "   $_" }
    Say "Quitarlos ahora NO los borra del historial publico. Si eran claves o contrasenas, considera que estan comprometidas: genera otras." Red
} else {
    Say "Historial: sin archivos prohibidos." Green
}

Say "`nListo." Cyan
if ($Apply) { Say "Ahora ejecuta: git status --short ; git add -A ; git commit -m `"Clean repo`" ; git push origin main" Yellow }

param([string[]]$Modules = @("tests.test_tui_setup"), [int]$Limit = 60)

# Запускает один-два тестовых модуля и печатает только строки с ошибками.
# Имена модулей -- с префиксом tests., как их зовёт `python -m`.
$env:PYTHONIOENCODING = "utf-8"
foreach ($m in $Modules) {
    $out = & uv run python -m $m 2>&1 | Out-String -Width 220
    Write-Output "===== $m exit=$LASTEXITCODE"
    ($out -split "`r?`n") |
        Where-Object { $_ -match "^(FAIL|ERROR): " -or $_ -match "AssertionError" -or $_ -match "Error:" -or $_ -match "line \d+, in test" } |
        Select-Object -First $Limit
}
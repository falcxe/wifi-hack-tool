param([string[]]$Files = @("_test_tui_setup.py"), [int]$Limit = 60)

$env:PYTHONIOENCODING = "utf-8"
foreach ($f in $Files) {
    $out = & python $f 2>&1 | Out-String -Width 220
    Write-Output "===== $f exit=$LASTEXITCODE"
    ($out -split "`r?`n") |
        Where-Object { $_ -match "^(FAIL|ERROR): " -or $_ -match "AssertionError" -or $_ -match "Error:" -or $_ -match "line \d+, in test" } |
        Select-Object -First $Limit
}

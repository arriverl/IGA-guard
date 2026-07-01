# IGA-Guard 2.0 周验收一键脚本
# 用法: .\scripts\week_acceptance.ps1 -Week 1
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 5)]
    [int]$Week
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

function Invoke-Step {
    param([string]$Name, [scriptblock]$Block)
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    & $Block
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "Step failed: $Name (exit $LASTEXITCODE)"
    }
}

switch ($Week) {
    1 {
        Invoke-Step "install deps" { pip install -r requirements.txt }
        Invoke-Step "generate dataset" { python scripts/generate_dataset.py --variants 5 }
        Invoke-Step "timeseries tests" { python -m pytest tests/test_timeseries_buffer.py -q }
        Invoke-Step "evaluate" { python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv }
        Invoke-Step "latency" { python scripts/benchmark_latency.py --iterations 1000 }
    }
    2 {
        Invoke-Step "install torch" { pip install torch transformers }
        Invoke-Step "generate dataset" { python scripts/generate_dataset.py --variants 10 }
        Invoke-Step "train bert" { python scripts/train_bert.py --data data/samples/obfuscated_dataset.csv --epochs 5 }
        Invoke-Step "train xgb" { python scripts/train.py --data data/samples/obfuscated_dataset.csv }
        Invoke-Step "evaluate" { python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv }
        Invoke-Step "latency" { python scripts/benchmark_latency.py --iterations 5000 }
    }
    3 {
        Invoke-Step "expand dataset" { python scripts/generate_dataset.py --variants 20 --output data/samples/obfuscated_10k.csv }
        Invoke-Step "evaluate 10k" { python scripts/evaluate.py --data data/samples/obfuscated_10k.csv }
        Invoke-Step "explainability" { python scripts/eval_explainability.py }
    }
    4 {
        Invoke-Step "evaluate" { python scripts/evaluate.py --data data/samples/obfuscated_10k.csv }
        Invoke-Step "latency 50k" { python scripts/benchmark_latency.py --iterations 50000 --warmup 500 }
        Invoke-Step "stress" { python scripts/stress_test.py --duration 60 --workers 8 }
        if (Test-Path "scripts/run_adversarial.py") {
            Invoke-Step "adversarial" { python scripts/run_adversarial.py --rounds 5 --output results/v2_exp3_adversarial_rounds.csv }
        } else {
            Write-Host "SKIP: scripts/run_adversarial.py not yet implemented (W4 deliverable)" -ForegroundColor Yellow
        }
        Invoke-Step "explainability" { python scripts/eval_explainability.py --output results/v2_exp6_localization.json }
    }
    5 {
        Invoke-Step "generate" { python scripts/generate_dataset.py --variants 10 }
        Invoke-Step "train xgb" { python scripts/train.py --data data/samples/obfuscated_dataset.csv }
        if (Test-Path "scripts/train_bert.py") {
            Invoke-Step "train bert" { python scripts/train_bert.py --data data/samples/obfuscated_dataset.csv --epochs 5 }
        }
        Invoke-Step "evaluate" { python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv }
        Invoke-Step "explainability" { python scripts/eval_explainability.py }
        Invoke-Step "latency" { python scripts/benchmark_latency.py --iterations 50000 }
        Invoke-Step "stress" { python scripts/stress_test.py --duration 30 }
    }
}

Write-Host "`nWeek $Week acceptance PASSED" -ForegroundColor Green

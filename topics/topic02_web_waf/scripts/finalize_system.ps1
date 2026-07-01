# IGA-Guard 2.0 最终系统一键部署
# 用法: powershell -ExecutionPolicy Bypass -File scripts\finalize_system.ps1

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $Root "..")
$env:PYTHONPATH = "src"

$LogDir = Join-Path $PWD "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Write-Host "========================================" -ForegroundColor Green
Write-Host " IGA-Guard 2.0 最终系统部署" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# 1. 社区种子 + 数据集（15万混淆）
Write-Host "`n[1/7] 构建社区种子与 master 数据集..." -ForegroundColor Yellow
python scripts/build_community_seed.py 2>&1 | Tee-Object (Join-Path $LogDir "finalize_seed.log")
python scripts/dataset_agent.py --skip-csic-download --skip-fetch --skip-community-fetch `
    --max-rows 60000 --max-obfuscated 150000 --obf-variants 4 `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_dataset.log")

# 2. 单元测试
Write-Host "`n[2/7] 冒烟测试..." -ForegroundColor Yellow
python -m pytest tests/test_pipeline_smoke.py tests/test_timeseries_buffer.py -q `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_pytest.log")

# 3. RF 训练
Write-Host "`n[3/7] 训练 Fusion RF..." -ForegroundColor Yellow
python scripts/train.py --data data/master/train_obfuscated.csv `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_train_rf.log")

# 4. TinyBERT（子集加速，可后台）
Write-Host "`n[4/7] 微调 TinyBERT（50k 样本）..." -ForegroundColor Yellow
python scripts/train_bert.py --data data/master/train_obfuscated.csv --epochs 3 --max-samples 50000 `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_train_bert.log")

# 5. 评估
Write-Host "`n[5/7] 全量评估（可抽样）..." -ForegroundColor Yellow
python scripts/evaluate.py --data data/master/test_obfuscated.csv --max-samples 8000 `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_eval.log")
python scripts/eval_explainability.py 2>&1 | Tee-Object (Join-Path $LogDir "finalize_explain.log")
python scripts/benchmark_latency.py --iterations 500 --warmup 100 `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_latency.log")

# 6. 对抗演化
Write-Host "`n[6/7] 对抗演化 3 轮..." -ForegroundColor Yellow
python scripts/run_adversarial.py --rounds 3 --data data/master/test.csv `
    2>&1 | Tee-Object (Join-Path $LogDir "finalize_adversarial.log")

# 7. 启动 Web
Write-Host "`n[7/7] 启动 Web 服务..." -ForegroundColor Yellow
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
Start-Process python -ArgumentList "run.py" -WorkingDirectory $PWD `
    -RedirectStandardOutput "$LogDir\web_finalize_$ts.log" `
    -RedirectStandardError "$LogDir\web_finalize_$ts.err" -WindowStyle Minimized
Start-Sleep -Seconds 3
try {
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -TimeoutSec 5
    Write-Host "  Web OK: $($h.status) v$($h.version)" -ForegroundColor Green
} catch {
    Write-Host "  Web 启动中，见 logs/web_finalize_*.log" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " 最终系统就绪" -ForegroundColor Green
Write-Host "  大屏: http://127.0.0.1:5000/" -ForegroundColor White
Write-Host "  数据: data/master/full_obfuscated.csv" -ForegroundColor White
Write-Host "  模型: models/fusion_detector.joblib + models/tinybert_waf/" -ForegroundColor White
Write-Host "  日志: logs/finalize_*.log" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green

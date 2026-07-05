# IGA-Guard 3.0 竞赛提交打包脚本
# 用法: powershell -ExecutionPolicy Bypass -File submission/package_submission.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $ProjectRoot "IGA-Guard3_submission"
$ZipPath = Join-Path $ProjectRoot "IGA-Guard3_submission.zip"

Write-Host "=== IGA-Guard 3.0 提交打包 ===" -ForegroundColor Cyan
Write-Host "项目根目录: $ProjectRoot"

# 清理旧输出
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
New-Item -ItemType Directory -Path $OutDir | Out-Null

# 1. 复制文档
Write-Host "[1/4] 复制提交文档..." -ForegroundColor Yellow
$docs = @(
    "submission\作品报告.md",
    "submission\测试报告.md",
    "submission\运行说明.md",
    "submission\交付物清单.md",
    "submission\原创性声明.svg",
    "submission\原创性声明说明.md",
    "submission\演示说明.txt"
)
foreach ($doc in $docs) {
    $src = Join-Path $ProjectRoot $doc
    if (Test-Path $src) {
        $destName = Split-Path $doc -Leaf
        Copy-Item $src (Join-Path $OutDir $destName)
        Write-Host "  + $destName"
    }
}

# 2. 打包源代码（排除无关目录）
Write-Host "[2/4] 打包源代码..." -ForegroundColor Yellow
$srcZip = Join-Path $OutDir "05_source_code.zip"
$tempSrc = Join-Path $ProjectRoot "_pack_staging"
if (Test-Path $tempSrc) { Remove-Item $tempSrc -Recurse -Force }
New-Item -ItemType Directory -Path $tempSrc | Out-Null

$includeItems = @(
    "src", "backend", "frontend", "scripts", "configs", "models",
    "data", "tests", "results", "docs", "submission",
    "run.py", "requirements.txt", "README.md", "AGENTS.md"
)
foreach ($item in $includeItems) {
    $src = Join-Path $ProjectRoot $item
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $tempSrc $item) -Recurse -Force
    }
}

Get-ChildItem $tempSrc -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $tempSrc -Recurse -Directory -Filter ".pytest_cache" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path $srcZip) { Remove-Item $srcZip -Force }
Compress-Archive -Path (Join-Path $tempSrc "*") -DestinationPath $srcZip -CompressionLevel Optimal
Remove-Item $tempSrc -Recurse -Force
$zipSize = [math]::Round((Get-Item $srcZip).Length / 1MB, 1)
Write-Host "  + 05_source_code.zip ($zipSize MB)"

# 3. 生成文件清单
Write-Host "[3/4] 生成文件清单..." -ForegroundColor Yellow
$manifest = @"
IGA-Guard 3.0 竞赛提交包
生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

文件列表:
$(Get-ChildItem $OutDir | ForEach-Object { "  - $($_.Name) ($([math]::Round($_.Length/1KB, 1)) KB)" })

待手动完成:
  [ ] 将 作品报告.md 导出为 01_作品报告.pdf
  [ ] 打印 原创性声明.svg → 签字盖章 → 扫描为 02_原创性声明.pdf
  [ ] 将 运行说明.md 导出为 03_运行说明.pdf
  [ ] 将 测试报告.md 导出为 04_测试报告.pdf

核心指标 (results/v2_exp1_overall.json):
  混淆 Recall: 99.95%
  混淆 Precision: 100%
  Normal FPR: 5.63%
  P50 延迟: 2.92ms
"@
$manifest | Out-File (Join-Path $OutDir "文件清单.txt") -Encoding UTF8

# 4. 打包总 zip
Write-Host "[4/4] 生成总压缩包..." -ForegroundColor Yellow
Compress-Archive -Path "$OutDir\*" -DestinationPath $ZipPath -Force

Write-Host ""
Write-Host "=== 打包完成 ===" -ForegroundColor Green
Write-Host "输出目录: $OutDir"
Write-Host "总压缩包: $ZipPath"
Write-Host ""
Write-Host "下一步:" -ForegroundColor Cyan
Write-Host "  1. 填写 作品报告.md 中的团队信息"
Write-Host "  2. 打印 原创性声明.svg 并签字盖章"
Write-Host "  3. 将 .md 文档导出为 PDF"
Write-Host "  4. 按 交付物清单.md 自检后提交"

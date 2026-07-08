# IGA-Guard Auto Verify Report

- **Started**: 2026-07-08T06:27:56.084359+00:00
- **Finished**: 2026-07-08T06:34:43.576354+00:00
- **Overall**: PASS
- **Elapsed**: 407.49s

## Gates

| Gate | Status | Detail |
| --- | --- | --- |
| pytest | PASS | all tests pass |
| llm | PASS | ollama reachable |
| e1_2k | PASS | obf_recall>=0.995, fpr<=0.05 (obf_recall=0.9991, fpr=0.0432, samples=2000) |
| e1_4k | PASS | obf_recall>=0.995, fpr<=0.05 (obf_recall=0.9981, fpr=0.0458, samples=4000) |
| e1_nocache | PASS | obf_recall>=0.992, fpr<=0.05 (obf_recall=0.9962, fpr=0.0288, samples=2000) |
| miss_to_rule | PASS | miss cluster → rescue rules |
| calibrate_fusion | PASS | fusion weight calibration |
| e4_latency | PASS | p50<=5.0ms, p99<=50.0ms (p50_ms=0.07, p99_ms=13.958) |
| e6_explain | PASS | span_hit>=1.0 or improvement>=0.22 (span_hit_rate=1.0, localization_improvement=0.3793) |
| e8_patch | PASS | block_rate>=1.0 (block_rate=1.0) |
| e9_40 | PASS | pooled/block recall gates (smoke) (pooled_recall=1.0, final_round_recall=1.0, block_recall=1.0, total_missed=0) |
| e9_80 | PASS | pooled/final/block recall gates (pooled_recall=1.0, final_round_recall=1.0, block_recall=1.0, total_missed=0) |

## Steps

- `pytest`: rc=0 elapsed=21.74s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/pytest.log`
- `check_llm`: rc=0 elapsed=13.2s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/check_llm.log`
- `e1_2k`: rc=0 elapsed=76.27s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_2k.log`
- `e1_4k`: rc=0 elapsed=139.79s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_4k.log`
- `e1_nocache`: rc=0 elapsed=42.66s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_nocache.log`
- `miss_to_rule`: rc=0 elapsed=1.59s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/miss_to_rule.log`
- `calibrate_fusion`: rc=0 elapsed=0.04s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/calibrate_fusion.log`
- `e4_latency`: rc=0 elapsed=16.08s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e4_latency.log`
- `e6_explain`: rc=0 elapsed=1.56s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e6_explain.log`
- `e8_patch`: rc=0 elapsed=1.47s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e8_patch.log`
- `e9_40`: rc=0 elapsed=47.12s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e9_40.log`
- `e9_80`: rc=0 elapsed=45.96s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e9_80.log`

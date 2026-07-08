# IGA-Guard Auto Verify Report

- **Started**: 2026-07-08T04:12:04.369272+00:00
- **Finished**: 2026-07-08T04:26:31.896399+00:00
- **Overall**: FAIL
- **Elapsed**: 867.53s

## Gates

| Gate | Status | Detail |
| --- | --- | --- |
| pytest | PASS | all tests pass |
| llm | PASS | ollama reachable |
| e1_2k | PASS | obf_recall>=0.995, fpr<=0.05 (obf_recall=0.9991, fpr=0.0432, samples=2000) |
| e1_4k | PASS | obf_recall>=0.995, fpr<=0.05 (obf_recall=0.9981, fpr=0.0458, samples=4000) |
| e1_nocache | PASS | obf_recall>=0.992, fpr<=0.05 (obf_recall=0.9953, fpr=0.0312, samples=2000) |
| e4_latency | FAIL | p50<=5.0ms, p99<=50.0ms (p50_ms=0.072, p99_ms=63.232) |
| e6_explain | FAIL | span_hit>=1.0 (span_hit_rate=0.0) |
| e8_patch | PASS | block_rate>=1.0 (block_rate=1.0) |
| e9_40 | FAIL | pooled/final/block recall gates (pooled_recall=0.775, final_round_recall=0.625, block_recall=0.775, total_missed=27) |
| e9_80 | PASS | pooled/final/block recall gates (pooled_recall=0.9896, final_round_recall=0.9818, block_recall=0.9896, total_missed=2) |

## Steps

- `pytest`: rc=0 elapsed=33.95s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/pytest.log`
- `check_llm`: rc=0 elapsed=10.85s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/check_llm.log`
- `e1_2k`: rc=0 elapsed=164.98s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_2k.log`
- `e1_4k`: rc=0 elapsed=325.73s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_4k.log`
- `e1_nocache`: rc=0 elapsed=52.75s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e1_nocache.log`
- `e4_latency`: rc=0 elapsed=36.84s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e4_latency.log`
- `e6_explain`: rc=0 elapsed=1.64s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e6_explain.log`
- `e8_patch`: rc=0 elapsed=1.58s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e8_patch.log`
- `e9_40`: rc=1 elapsed=132.84s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e9_40.log`
- `e9_80`: rc=0 elapsed=106.36s log=`/root/autodl-tmp/IGA-Guard/IGA-guard/topics/topic02_web_waf/data/cache/auto_verify_logs/e9_80.log`

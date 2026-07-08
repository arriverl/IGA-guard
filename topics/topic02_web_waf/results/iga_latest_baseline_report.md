# IGA-Guard 最新基线研判

## 指标快照

| 口径 | 样本 | Overall Recall | Normal FPR | Obfuscated Recall | Exact-Class Recall/Acc |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2k v7 CSIC | 2000 | 0.8926 | 0.0719 | 0.9981 | 0.6222 / 0.6865 |
| 4k v6 | 4000 | 0.8967 | 0.0676 | 0.9972 | 0.7358 / 0.7808 |
| E9 80 v2 | 197 variants | 1.0000 pooled | 0 misses | 1.0000 final | passed |
| E4 latency | 1000 iter | - | - | - | P50 0.075ms / P99 106.023ms |

## 结论

- 混淆攻击召回已稳定超过 0.995，当前优化重点不应继续粗暴提高攻击阈值或全局规则激进度。
- 2k/4k Normal FPR 仍在 6.7% 到 7.2%，主要来自 CSIC 正常表单、购物车字段和西语地址字段。
- E9 已有一次 80 variants 全检出，但需要在每次 FP/召回规则调整后复测，防止 hex32/HPP/HTML entity 逃逸回归。
- E4 P50 很低但 P99 高，说明热点路径存在少量重分支或重复计算，应先做无行为变化的规则信号去重。

## 当前优先级

1. 先压 FP：CSIC form/address/shopping cart 护栏、弱 SQLi 结构分收紧、pipeline 聚合良性反转。
2. 再补召回：hex32/HPP/high-entropy 只在攻击上下文下 rescue，避免恢复 v4 的高 FPR。
3. 再做性能：复用 kw/st/evasion 计算结果，减少 P95/P99 长尾。
4. 最后全量验证：2k -> 4k -> E9 40/80 -> E1 cache/no-cache -> E4/E6/E8。

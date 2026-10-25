package upstream

import "testing"

// v0.12.80 钉子：签到入账数额回退语义——credits 与 extra_credits
// 取其一（credits 优先），永不相加。
//
// 依据（magpie ba9801c，2026-10-24，yetone 采纳 zhujiu 的 magpie Discord
// 实测报告）：Trae CN 签到 status 返回 credits=100 + extra_credits=100 时，
// 官方面板相加显示 200，实际只到账 100——两字段是同一份当日奖励的
// 两种表述（基础表述 vs 会员加码表述），不是可叠加的两笔。
// 我们的旧行为（v0.12.31 起）恰好复刻了官方面板的双计误读。
func TestCheckinAwardedTakesOneNeverSums(t *testing.T) {
	cases := []struct {
		name           string
		credits, extra int64
		want           int64
	}{
		// zhujiu 实测现场：100+100 显示 200 实到 100 —— 相加即复现双计。
		{"zhujiu field report 100+100 -> 100", 100, 100, 100},
		{"base only", 150, 0, 150},
		{"no base, member bonus only", 0, 50, 50},
		{"both zero", 0, 0, 0},
		{"negative credits treated as absent", -1, 50, 50},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckinAwarded(c.credits, c.extra)
			if got != c.want {
				t.Fatalf("CheckinAwarded(%d, %d) = %d, want %d (take-one semantics, never sum)",
					c.credits, c.extra, got, c.want)
			}
			if c.credits > 0 && c.extra > 0 && got == c.credits+c.extra {
				t.Fatalf("CheckinAwarded(%d, %d) = %d equals the sum — the v0.12.31 double-count is back",
					c.credits, c.extra, got)
			}
		})
	}
}

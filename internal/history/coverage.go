package history

import (
	"github.com/ruiwenya/WinTraceLens/internal/coverage"
	"strings"
)

func historyCoverage(snapshot Snapshot, limit int) *coverage.Summary {
	c := &coverage.Summary{Status: "Insufficient telemetry", Returned: len(snapshot.Records), Limit: limit, LimitScope: "每来源", Sort: "每来源时间降序；无时间的 DNS 缓存不代表历史时间", Warnings: append([]string(nil), snapshot.CollectionErrors...), Boundary: "关键网络审计源未返回可用历史记录；本模块的阴性结果不能用于排除历史外联。当前快照和 DNS 缓存不能还原未记录的通信。"}
	counts := map[string]int{}
	var times []string
	for _, record := range snapshot.Records {
		counts[record.Source]++
		if record.Time != "" {
			times = append(times, record.Time)
		}
		lower := strings.ToLower(record.Source)
		if record.Time != "" && (strings.Contains(lower, "sysmon") || strings.Contains(lower, "wfp") || strings.Contains(lower, "防火墙") || strings.Contains(lower, "dns client")) {
			c.Status = "Observed"
		}
	}
	for source, count := range counts {
		c.Sources = append(c.Sources, source)
		if count >= limit {
			c.LimitReached = true
			c.PossiblyTruncated = true
		}
	}
	if c.Status == "Observed" {
		c.Boundary = "已观察到部分历史日志；证据受日志源、审计策略、时间窗和采集配额限制，未命中仍不能证明没有历史外联。"
	}
	c.Earliest, c.Latest = coverage.Times(times)
	return c
}

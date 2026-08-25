package systemtools

import (
	"fmt"
	"strings"
)

type Tool struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Command   string `json:"command"`
	Arguments string `json:"arguments,omitempty"`
}

var allowedTools = map[string]Tool{
	"services": {ID: "services", Label: "服务管理器", Command: "services.msc"},
	"tasks":    {ID: "tasks", Label: "任务计划程序", Command: "taskschd.msc"},
	"startup":  {ID: "startup", Label: "任务管理器启动项", Command: "taskmgr.exe", Arguments: "/0 /startup"},
	"users":    {ID: "users", Label: "本地用户和组", Command: "lusrmgr.msc"},
	"registry": {ID: "registry", Label: "注册表", Command: "regedit.exe"},
}

func Resolve(id string) (Tool, error) {
	key := strings.ToLower(strings.TrimSpace(id))
	if tool, ok := allowedTools[key]; ok {
		return tool, nil
	}
	return Tool{}, fmt.Errorf("不支持的系统工具: %s", id)
}

func List() []Tool {
	order := []string{"services", "tasks", "startup", "users", "registry"}
	out := make([]Tool, 0, len(order))
	for _, id := range order {
		out = append(out, allowedTools[id])
	}
	return out
}

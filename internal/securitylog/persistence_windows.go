//go:build windows

package securitylog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

// CollectPersistenceMatches filters at the log source by exact service name,
// so a busy Security log cannot crowd out referenced installation events.
func CollectPersistenceMatches(names []string) ([]PreservedEvent, []string) {
	var queries []struct{ Channel, XPath string }
	var warnings []string
	for i, name := range names {
		if i >= 16 {
			warnings = append(warnings, "关联服务事件达到 16 个服务上限；其余服务未执行定向事件查询。")
			break
		}
		literal, ok := eventXPathLiteral(name)
		if !ok {
			warnings = append(warnings, "服务名包含无法用于 Windows XPath 的引号，未执行该项事件查询")
			continue
		}
		for _, channel := range []string{"System", "Security"} {
			id := 7045
			if channel == "Security" {
				id = 4697
			}
			xpath := fmt.Sprintf("*[System[EventID=%d] and EventData[Data[@Name='ServiceName']=%s or Data[@Name='param1']=%s]]", id, literal, literal)
			queries = append(queries, struct{ Channel, XPath string }{channel, xpath})
		}
	}
	if len(queries) == 0 {
		return nil, warnings
	}
	raw, _ := json.Marshal(queries)
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$queries = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(raw) + `')) | ConvertFrom-Json)
$events = New-Object 'System.Collections.Generic.List[object]'
$errors = New-Object 'System.Collections.Generic.List[string]'
foreach ($q in $queries) {
  try {
    $rows = @(Get-WinEvent -LogName $q.Channel -FilterXPath $q.XPath -MaxEvents 21 -ErrorAction Stop)
    if ($rows.Count -gt 20) { $errors.Add($q.Channel + ': 关联服务事件达到每服务每通道 20 条上限，保留最新记录。') }
    foreach ($e in @($rows | Select-Object -First 20)) {
      [xml]$x = $e.ToXml()
      $d = @{}
      foreach ($v in @($x.Event.EventData.Data)) { $d[[string]$v.Name] = [string]$v.'#text' }
      $events.Add([pscustomobject]@{
        Time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); TimeUTC=$e.TimeCreated.ToUniversalTime().ToString('o')
        Source=$q.Channel; Channel=$e.LogName; Provider=$e.ProviderName; Computer=$e.MachineName
        EventID=[string]$e.Id; RecordID=[string]$e.RecordId; ServiceName=[string]$d.ServiceName
        ImagePath=($(if($d.ImagePath){$d.ImagePath}else{$d.ServiceFileName})); Account=($(if($d.AccountName){$d.AccountName}else{$d.ServiceAccount}))
        ServiceType=[string]$d.ServiceType; StartType=($(if($d.StartType){$d.StartType}else{$d.ServiceStartType}))
        SubjectSID=[string]$d.SubjectUserSid; Message=[string]$e.Message; XML=[string]$e.ToXml(); Details='按服务名定向查询，不受普通事件列表上限限制'
      })
    }
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $errors.Add($q.Channel + ': ' + $_.Exception.Message) }
  }
}
[pscustomobject]@{events=@($events.ToArray()); collectionErrors=@($errors.ToArray())} | ConvertTo-Json -Compress -Depth 5
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := winexec.PowerShellContext(ctx, script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, append(warnings, "关联服务事件补采失败或超时；未确认服务安装时间："+err.Error())
	}
	var result struct {
		Events []PreservedEvent `json:"events"`
		Errors []string         `json:"collectionErrors"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xef, 0xbb, 0xbf}), &result); err != nil {
		return nil, append(warnings, "关联服务事件解析失败："+err.Error())
	}
	return result.Events, append(warnings, localizeErrors(result.Errors)...)
}

func eventXPathLiteral(value string) (string, bool) {
	if !strings.Contains(value, "'") {
		return "'" + value + "'", true
	}
	if !strings.Contains(value, `"`) {
		return `"` + value + `"`, true
	}
	return "", false
}

package coredns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/console-dns/client"
	"github.com/console-dns/spec/models"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
)

type ConsoleDns struct {
	client []*client.ConsoleDnsClient // dns 客户端

	Next  plugin.Handler
	Zones *models.Zones // 区域信息
	ETag  string        // 区域sha

	rwLock *sync.RWMutex

	logLevel int        // 日志等级
	cron     *cron.Cron // 计划任务
	Cache    string     // 本地缓存
}

func (c *ConsoleDns) Error(msg string, args ...any) {
	if c.logLevel <= 3 {
		log.Printf("plugin/console ERROR:"+msg+"\n", args...)
	}
}

func (c *ConsoleDns) Info(msg string, args ...any) {
	if c.logLevel <= 2 {
		log.Printf("plugin/console INFO:"+msg+"\n", args...)
	}
}
func (c *ConsoleDns) Debug(msg string, args ...any) {
	if c.logLevel <= 1 {
		log.Printf("plugin/console DEBUG:"+msg+"\n", args...)
	}
}

func (c *ConsoleDns) Name() string {
	return "console"
}

func (c *ConsoleDns) Start() {
	if c.Cache != "" {
		c.Info("读入缓存文件 %s", c.Cache)
		data, err := os.ReadFile(c.Cache)
		if err == nil {
			err := json.Unmarshal(data, &c.Zones)
			if err != nil {
				c.Error("缓存文件初始化失败: %v", err)
			}
		}
	}
	_, _ = c.cron.AddFunc("@every 10s", func() {
		c.fetch()
	})
	c.cron.Start()
	c.Info("console dns 初始化完成")
}

func (c *ConsoleDns) fetch() {
	var nextZone *models.Zones
	var err error
	var svc string
	var resp *http.Response
	for _, dnsClient := range c.client {
		svc = dnsClient.Server
		nextZone, resp, err = dnsClient.ListZones()
		if err == nil {
			break
		}
	}
	if err != nil {
		c.Error("记录拉取失败：%v", err)
		return
	}
	eTag := resp.Header.Get("ETag")
	if c.ETag != eTag {
		c.rwLock.Lock()
		defer c.rwLock.Unlock()
		c.Zones = nextZone
		c.Info("更新DNS本地缓存")
		c.flush()
		keys := reflect.ValueOf(nextZone.Zones).MapKeys()
		c.Info("从 %s 拉取/更新记录 %d 条 (%v)", svc, len(nextZone.Zones), keys)
		c.ETag = eTag
	} else {
		c.Debug("从 %s 拉取DNS记录完成，但内容无变化", svc)
	}
}

func (c *ConsoleDns) flush() {
	if c.Cache != "" {
		body, _ := json.Marshal(c.Zones)
		err := os.WriteFile(c.Cache, body, 0600)
		if err != nil {
			c.Error("缓存文件写入失败, %v", err.Error())
		}
	}
}

var (
	ErrNoZones  = errors.New("未匹配到区域")
	ErrNoRecord = errors.New("未匹配到记录")
)

func (c *ConsoleDns) QueryRecord(host, dType string) (zone string, record string, err error) {
	c.Debug("按照类型搜索区域 (%s) - %s", host, dType)
	host = strings.TrimSuffix(host, ".")
	pattens := strings.Split(host, ".")

	var z *models.Zone
	for i := 2; i <= len(pattens); i++ {
		n := strings.SplitN(host, ".", i)
		match := c.Zones.Zones[n[len(n)-1]]
		if match != nil {
			zone = n[len(n)-1]
			record = strings.Join(n[:len(n)-1], ".")
			z = match
			break
		}
	}
	// 命中根域
	if c.Zones.Zones[host] != nil {
		zone = host
		record = "@"
		z = c.Zones.Zones[host]
	}
	c.Debug("粗略的命中 %s - %s", record, zone)
	if z == nil {
		return "", "", errors.Wrapf(ErrNoZones, "%s", host)
	}
	r := z.Records[record]
	if r != nil && !recordExists(r, dType) {
		// 不存在记录，回退到 *
		r = nil
	}
	if r == nil {
		lc := strings.SplitN(record, ".", 2)
		if len(lc) == 2 {
			record = fmt.Sprintf("*.%s", lc[1])
			r = z.Records[record]
		} else {
			record = "*"
			r = z.Records["*"]
		}
	}
	if r != nil && !recordExists(r, dType) {
		// 不存在记录，回退到 @
		r = nil
	}
	if r == nil {
		record = "@"
		r = z.Records["@"]
	}
	if r != nil && !recordExists(r, dType) {
		// 不存在记录，清理
		r = nil
	}
	if r == nil {
		return "", "", errors.Wrapf(ErrNoRecord, "%s", record)
	}
	return zone, record, nil
}

func (c *ConsoleDns) hosts(host string) []dns.RR {
	result := make([]dns.RR, 0)
	zone, record, err := c.QueryRecord(host, "A")
	if err == nil {
		answers, _ := c.GetRecordA(zone, record, host)
		result = append(result, answers...)
	}
	zone, record, err = c.QueryRecord(host, "AAAA")
	if err == nil {
		answers, _ := c.GetRecordAAAA(zone, record, host)
		result = append(result, answers...)
	}
	return result
}

func (c *ConsoleDns) record(zone, record string, r func(record *models.Record)) {
	z := c.Zones.Zones[zone]
	if z != nil {
		re := z.Records[record]
		if re != nil {
			r(re)
		}
	}
}

func recordExists(record *models.Record, rType string) bool {
	switch rType {
	case "A":
		return len(record.A) != 0
	case "AAAA":
		return len(record.AAAA) != 0
	case "TXT":
		return len(record.TXT) != 0
	case "CNAME":
		return len(record.CNAME) != 0
	case "NS":
		return len(record.NS) != 0
	case "MX":
		return len(record.MX) != 0
	case "SRV":
		return len(record.SRV) != 0
	case "CAA":
		return len(record.CAA) != 0
	case "SOA":
		return record.SOA != nil
	default:
		return false
	}

}

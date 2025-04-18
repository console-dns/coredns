package coredns

import (
	"errors"
	"net/url"
	"strings"
	"sync"

	"github.com/console-dns/client"
	"github.com/console-dns/spec/models"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/robfig/cron/v3"
)

// init registers this plugin.
func init() {
	plugin.Register("console", setup)
}

func setup(c *caddy.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return plugin.Error("console", err)
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		config.Next = next
		return config
	})
	return nil
}

func parseConfig(c *caddy.Controller) (*ConsoleDns, error) {
	result := &ConsoleDns{
		client:   make([]*client.ConsoleDnsClient, 0),
		Next:     nil,
		Zones:    models.NewZones(),
		cron:     cron.New(),
		logLevel: 3,
		rwLock:   &sync.RWMutex{},
	}
	services := make([]string, 0)
	var token string
	for c.Next() {
		if c.NextBlock() {
			for {
				switch c.Val() {
				case "server":
					for c.NextArg() {
						_, err := url.Parse(c.Val())
						if err != nil {
							return nil, errors.Join(c.ArgErr(), err)
						} else {
							services = append(services, c.Val())
						}
					}
				case "token":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					token = c.Val()
				case "cache":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					result.Cache = c.Val()
				case "log":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					switch strings.ToUpper(c.Val()) {
					case "DEBUG":
						result.logLevel = 1
					case "INFO":
						result.logLevel = 2
					case "ERROR":
						result.logLevel = 3
					default:
						return nil, c.ArgErr()
					}
				default:
					if c.Val() != "}" {
						return nil, c.Errf("unknown property '%s'", c.Val())
					}
				}
				if !c.Next() {
					break
				}
			}
		}
	}
	if len(services) > 1 {
		result.Info("当前已配置故障转移服务 %v", services)
	}
	if len(services) == 0 || token == "" {
		return nil, errors.New("server 或 token 不能为空")
	}
	for _, service := range services {
		result.client = append(result.client, client.NewConsoleDnsClient(service, token))
	}
	result.Start()
	return result, nil
}

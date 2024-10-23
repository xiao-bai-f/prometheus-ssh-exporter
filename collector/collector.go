package collector

import (
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	stdlog "log"
	"ssh-exporter/utils"
	"sync"
)

const namespace = "ssh-exporter"

var (
	upDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"'1' if a scrape of the ssh device was successful, '0' otherwise.",
		[]string{"collector"},
		nil,
	)
)

type collector interface {
	Name() string
	Cmd() string
	Args() []string
	Collect(client *utils.SshClient, logger log.Logger, ch chan<- prometheus.Metric) (int, error)
}

// NodeCollector implements the prometheus.Collector interface.
type SshCollector struct {
	Logger log.Logger
	Target string
	Module string
	Config *SafeConfig
}

// Describe implements the prometheus.Collector interface.
func (c SshCollector) Describe(ch chan<- *prometheus.Desc) {

}

// Collect implements the prometheus.Collector interface.
func (c SshCollector) Collect(ch chan<- prometheus.Metric) {
	// 从解析采集配置
	moduleConfig := c.Config.ConfigForTarget(c.Logger, c.Target, c.Module)

	// 轮询执行采集任务
	// 创建ssh连接
	sshConfig := utils.SshConfig{
		Target:         c.Target,
		User:           moduleConfig.User,
		Password:       moduleConfig.Password,
		PrivateKeyPath: moduleConfig.PrivateKeyPath,
	}
	client, err := utils.NewSshClient(sshConfig)

	if err != nil {
		stdlog.Println("create ssh connect failed")
		return
	}

	wg := sync.WaitGroup{}
	collectors := moduleConfig.GetCollectors()
	wg.Add(len(collectors))
	for _, coll := range collectors {
		go func(coll collector) {
			up, _ := coll.Collect(client, c.Logger, ch)
			markCollectorUp(ch, coll.Name(), up)
			wg.Done()
		}(coll)
	}
	wg.Wait()
	// 关闭ssh连接
	client.Close()
}

func markCollectorUp(ch chan<- prometheus.Metric, name string, up int) {
	ch <- prometheus.MustNewConstMetric(
		upDesc,
		prometheus.GaugeValue,
		float64(up),
		name,
	)
}

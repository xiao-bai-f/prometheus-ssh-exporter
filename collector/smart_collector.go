package collector

import (
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
	stdlog "log"
	"os/exec"
	"ssh-exporter/utils"
)

var (
	SmartCollectorName = "smart"
	DEVS               = "devs"

	upStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_status"),
		"redis check the result 0 is normal, and 1 is not normal",
		[]string{"device"},
		nil,
	)
)

// Device
type Device struct {
	Name      string `json:"name"`
	Info_Name string `json:"info_name"`
	Type      string `json:"type"`
}

type SmartCollector struct {
	devs           []string
	privateKeyPath string
}

func (c SmartCollector) Name() string {
	return SmartCollectorName
}

func (c SmartCollector) Cmd() string {
	return "smartctl -A --json "
}

func (c SmartCollector) Args() []string {
	return nil
}

func (c SmartCollector) Collect(client *utils.SshClient, logger log.Logger, ch chan<- prometheus.Metric) (int, error) {
	// 1. 扫描device
	// todo 全量扫描追击磁盘，有bug，当磁盘做了ready，无法获取实际磁盘信息
	/*	json := readSMARTctlDevices(logger)
		scanDevices := json.Get("devices").Array()

		for _, d := range scanDevices {

			deviceName := extractDiskName(strings.TrimSpace(d.Get("info_name").String()))

		}*/

	for _, dev := range c.devs {
		result, err := client.ExecCommand(c.Cmd() + dev)
		if err != nil {
			stdlog.Print("msg", "S.M.A.R.T. output reading", "err", err, "device", dev)
			continue
		}
		device := Device{
			Info_Name: dev,
		}

		json := parseJSON(result)
		rcOk := resultCodeIsOk(logger, device, json.Get("smartctl.exit_status").Int())

		if !rcOk {
			ch <- prometheus.MustNewConstMetric(
				upStatus,
				prometheus.GaugeValue,
				0,
				device.Info_Name,
			)
			continue
		} else {
			ch <- prometheus.MustNewConstMetric(
				upStatus,
				prometheus.GaugeValue,
				1,
				device.Info_Name,
			)
		}

		smart := NewSMARTctl(logger, json, ch)
		smart.Collect()

	}

	return 1, nil
}

// Parse json to gjson object
func parseJSON(data string) gjson.Result {
	if !gjson.Valid(data) {
		return gjson.Parse("{}")
	}
	return gjson.Parse(data)
}

// Parse smartctl return code
func resultCodeIsOk(logger log.Logger, device Device, SMARTCtlResult int64) bool {
	result := true
	if SMARTCtlResult > 0 {
		b := SMARTCtlResult
		if (b & 1) != 0 {
			level.Error(logger).Log("msg", "Command line did not parse", "device", device.Info_Name)
			result = false
		}
		if (b & (1 << 1)) != 0 {
			level.Error(logger).Log("msg", "Device open failed, device did not return an IDENTIFY DEVICE structure, or device is in a low-power mode", "device", device.Info_Name)
			result = false
		}
		if (b & (1 << 2)) != 0 {
			level.Warn(logger).Log("msg", "Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure", "device", device.Info_Name)
		}
		if (b & (1 << 3)) != 0 {
			level.Warn(logger).Log("msg", "SMART status check returned 'DISK FAILING'", "device", device.Info_Name)
		}
		if (b & (1 << 4)) != 0 {
			level.Warn(logger).Log("msg", "We found prefail Attributes <= threshold", "device", device.Info_Name)
		}
		if (b & (1 << 5)) != 0 {
			level.Warn(logger).Log("msg", "SMART status check returned 'DISK OK' but we found that some (usage or prefail) Attributes have been <= threshold at some time in the past", "device", device.Info_Name)
		}
		if (b & (1 << 6)) != 0 {
			level.Warn(logger).Log("msg", "The device error log contains records of errors", "device", device.Info_Name)
		}
		if (b & (1 << 7)) != 0 {
			level.Warn(logger).Log("msg", "The device self-test log contains records of errors. [ATA only] Failed self-tests outdated by a newer successful extended self-test are ignored", "device", device.Info_Name)
		}
	}
	return result
}

func readSMARTctlDevices(logger log.Logger) gjson.Result {
	level.Debug(logger).Log("msg", "Scanning for devices")
	out, err := exec.Command("smartctl", "--json", "--scan").Output()
	if exiterr, ok := err.(*exec.ExitError); ok {
		level.Debug(logger).Log("msg", "Exit Status", "exit_code", exiterr.ExitCode())
		// The smartctl command returns 2 if devices are sleeping, ignore this error.
		if exiterr.ExitCode() != 2 {
			level.Warn(logger).Log("msg", "S.M.A.R.T. output reading error", "err", err)
			return gjson.Result{}
		}
	}
	return parseJSON(string(out))
}

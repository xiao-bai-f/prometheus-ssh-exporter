package collector

import (
	"errors"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"gopkg.in/yaml.v3"
	stdlog "log"
	"os"
	"strings"
	"sync"
)

const (
	targetLocal = ""
)

type CollectorName = map[string]map[string]string

type ScrapeConfig struct {
	Ssh []*SshConfig `yaml:"ssh"`
}

type SshConfig struct {
	Ip     string        `yaml:"ip"`
	Models []interface{} `yaml:"models"`
}

type ModuleConfig struct {
	User           string          `yaml:"user"`
	Password       string          `yaml:"password"`
	PrivateKeyPath string          `yaml:"private_key_path"`
	Timeout        uint32          `yaml:"timeout"`
	Collectors     []CollectorName `yaml:"collectors,omitempty"`
}

type Config struct {
	Modules map[string]ModuleConfig `yaml:"modules,omitempty"`
}

// SafeConfig wraps Config for concurrency-safe operations.
type SafeConfig struct {
	sync.RWMutex
	C *Config
}

func (tc ModuleConfig) GetCollectors() []collector {
	result := []collector{}
	for _, co := range tc.Collectors {
		i, err := tc.GetInstance(co)
		if err != nil {
			stdlog.Println(err)
			continue
		}
		result = append(result, i)
	}
	return result
}

func (tc ModuleConfig) GetInstance(cn CollectorName) (collector, error) {
	for labelName, labelValue := range cn {
		switch labelName {
		case SmartCollectorName:
			return parseSmart(labelValue)
		}

	}

	return nil, errors.New("module is empty")
}

func parseSmart(labelValue interface{}) (collector, error) {
	if labelValue == nil {
		return nil, errors.New("SmartCollectorName is empty")
	}
	scrapeConfig, ok := labelValue.(map[string]string)
	if !ok {
		return nil, errors.New("SmartCollectorName parse failed")
	}
	if scrapeConfig[DEVS] == "" {
		return nil, errors.New("SmartCollectorName devs convert to string[] failed or devs length is 0")
	}

	devs := strings.Split(scrapeConfig[DEVS], ",")

	return SmartCollector{
		devs: devs,
	}, nil
}

// ReloadConfig reloads the config in a concurrency-safe way. If the configFile
// is unreadable or unparsable, an error is returned and the old config is kept.
func (sc *SafeConfig) ReloadConfig(logger log.Logger, configFile string) error {
	var c = &Config{}
	var config []byte
	var err error

	if configFile != "" {
		config, err = os.ReadFile(configFile)
		if err != nil {
			level.Error(logger).Log("msg", "Error reading config file", "error", err)
			return err
		}
	} else {
		config = []byte("# use empty file as default")
	}

	if err = yaml.Unmarshal(config, c); err != nil {
		return err
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	if configFile != "" {
		level.Info(logger).Log("msg", "Loaded config file", "path", configFile)
	}
	return nil
}

func (sc *SafeConfig) ConfigForTarget(logger log.Logger, target, module string) ModuleConfig {
	sc.Lock()
	defer sc.Unlock()

	var config ModuleConfig
	var ok = false

	if module != "default" {
		config, ok = sc.C.Modules[module]
		if !ok {
			level.Error(logger).Log("msg", "Requested module not found, using default", "module", module, "target", targetName(target))
		}
	}

	// If nothing found, fall back to defaults
	if !ok {
		config, ok = sc.C.Modules["default"]
		if !ok {
			level.Debug(logger).Log("msg", "Needed default config for, but none configured, using FreeIPMI defaults", "target", targetName(target))
		}
	}

	return config

}

func targetName(target string) string {
	if target == targetLocal {
		return "[local]"
	}
	return target
}

// Copyright 2022 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
)

var (
	metricSmartctlVersion = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "version"),

		"smartctl version",
		[]string{
			"json_format_version",
			"smartctl_version",
			"svn_revision",
			"build_info",
		},
		nil,
	)
	metricDeviceModel = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device"),
		"Device info",
		[]string{
			"device",
			"interface",
			"protocol",
			"model_family",
			"model_name",
			"serial_number",
			"ata_additional_product_id",
			"firmware_version",
			"ata_version",
			"sata_version",
			"form_factor",
			// scsi_model_name is mapped into model_name
			"scsi_vendor",
			"scsi_product",
			"scsi_revision",
			"scsi_version",
		},
		nil,
	)
	metricDeviceCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "devices"),
		"Number of devices configured or dynamically discovered",
		[]string{},
		nil,
	)
	metricDeviceCapacityBlocks = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_capacity_blocks"),
		"Device capacity in blocks",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceCapacityBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_capacity_bytes"),
		"Device capacity in bytes",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceTotalCapacityBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_nvme_capacity_bytes"),
		"NVMe device total capacity bytes",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceBlockSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_block_size"),
		"Device block size",
		[]string{
			"device",
			"blocks_type",
		},
		nil,
	)
	metricDeviceInterfaceSpeed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_interface_speed"),
		"Device interface speed, bits per second",
		[]string{
			"device",
			"speed_type",
		},
		nil,
	)
	metricDeviceAttribute = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_attribute"),
		"Device attributes",
		[]string{
			"device",
			"attribute_name",
			"attribute_flags_short",
			"attribute_flags_long",
			"attribute_value_type",
			"attribute_id",
		},
		nil,
	)
	metricDevicePowerOnSeconds = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_power_on_seconds"),
		"Device power on seconds",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceRotationRate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_rotation_rate"),
		"Device rotation rate",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceTemperature = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_temperature"),
		"Device temperature celsius",
		[]string{
			"device",
			"temperature_type",
		},
		nil,
	)
	metricDevicePowerCycleCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_power_cycle_count"),
		"Device power cycle count",
		[]string{
			"device",
		},
		nil,
	)
	metricDevicePercentageUsed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_percentage_used"),
		"Device write percentage used",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceAvailableSpare = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_available_spare"),
		"Normalized percentage (0 to 100%) of the remaining spare capacity available",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceAvailableSpareThreshold = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_available_spare_threshold"),
		"When the Available Spare falls below the threshold indicated in this field, an asynchronous event completion may occur. The value is indicated as a normalized percentage (0 to 100%)",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceCriticalWarning = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_critical_warning"),
		"This field indicates critical warnings for the state of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceWarningTempTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_warning_temp_time"),
		"This field indicates critical warnings for the state of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceCriticalCompTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_critical_comp_time"),
		"This field indicates critical warnings for the state of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceMediaErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_media_errors"),
		"Contains the number of occurrences where the controller detected an unrecovered data integrity error. Errors such as uncorrectable ECC, CRC checksum failure, or LBA tag mismatch are included in this field",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceNumErrLogEntries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_num_err_log_entries"),
		"Contains the number of Error Information log entries over the life of the controller",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceBytesRead = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_bytes_read"),
		"",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceBytesWritten = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_bytes_written"),
		"",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceSmartStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_smart_status"),
		"General smart status",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceExitStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_smartctl_exit_status"),
		"Exit status of smartctl on device",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_state"),
		"Device state (0=active, 1=standby, 2=sleep, 3=dst, 4=offline, 5=sct)",
		[]string{
			"device",
		},
		nil,
	)
	metricDeviceStatistics = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_statistics"),
		"Device statistics",
		[]string{
			"device",
			"statistic_table",
			"statistic_name",
			"statistic_flags_short",
			"statistic_flags_long",
		},
		nil,
	)
	metricDeviceErrorLogCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_error_log_count"),
		"Device SMART error log count",
		[]string{
			"device",
			"error_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_self_test_log_count"),
		"Device SMART self test log count",
		[]string{
			"device",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogErrorCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_self_test_log_error_count"),
		"Device SMART self test log error count",
		[]string{
			"device",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceERCSeconds = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "device_erc_seconds"),
		"Device SMART Error Recovery Control Seconds",
		[]string{
			"device",
			"op_type",
		},
		nil,
	)
	metricSCSIGrownDefectList = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "scsi_grown_defect_list"),
		"Device SCSI grown defect list counter",
		[]string{
			"device",
		},
		nil,
	)
	metricReadErrorsCorrectedByRereadsRewrites = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "read_errors_corrected_by_rereads_rewrites"),
		"Read Errors Corrected by ReReads/ReWrites",
		[]string{
			"device",
		},
		nil,
	)
	metricReadErrorsCorrectedByEccFast = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "read_errors_corrected_by_eccfast"),
		"Read Errors Corrected by ECC Fast",
		[]string{
			"device",
		},
		nil,
	)
	metricReadErrorsCorrectedByEccDelayed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "read_errors_corrected_by_eccdelayed"),
		"Read Errors Corrected by ECC Delayed",
		[]string{
			"device",
		},
		nil,
	)
	metricReadTotalUncorrectedErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "read_total_uncorrected_errors"),
		"Read Total Uncorrected Errors",
		[]string{
			"device",
		},
		nil,
	)
	metricWriteErrorsCorrectedByRereadsRewrites = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "write_errors_corrected_by_rereads_rewrites"),
		"Write Errors Corrected by ReReads/ReWrites",
		[]string{
			"device",
		},
		nil,
	)
	metricWriteErrorsCorrectedByEccFast = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "write_errors_corrected_by_eccfast"),
		"Write Errors Corrected by ECC Fast",
		[]string{
			"device",
		},
		nil,
	)
	metricWriteErrorsCorrectedByEccDelayed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "write_errors_corrected_by_eccdelayed"),
		"Write Errors Corrected by ECC Delayed",
		[]string{
			"device",
		},
		nil,
	)
	metricWriteTotalUncorrectedErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "smartctl", "write_total_uncorrected_errors"),
		"Write Total Uncorrected Errors",
		[]string{
			"device",
		},
		nil,
	)
)

// SMARTDevice - short info about device
type SMARTDevice struct {
	device string
	serial string
	family string
	model  string
	// These are used to select types of metrics.
	interface_ string
	protocol   string
}

// SMARTctl object
type SMARTctl struct {
	ch     chan<- prometheus.Metric
	json   gjson.Result
	logger log.Logger
	device SMARTDevice
}

func extractDiskName(input string) string {
	re := regexp.MustCompile(`^(?:/dev/(?P<bus_name>\S+)/(?P<bus_num>\S+)\s\[|/dev/|\[)(?:\s\[|)(?P<disk>[a-z0-9_]+)(?:\].*|)$`)
	match := re.FindStringSubmatch(input)

	if len(match) > 0 {
		busNameIndex := re.SubexpIndex("bus_name")
		busNumIndex := re.SubexpIndex("bus_num")
		diskIndex := re.SubexpIndex("disk")
		var name []string
		if busNameIndex != -1 && match[busNameIndex] != "" {
			name = append(name, match[busNameIndex])
		}
		if busNumIndex != -1 && match[busNumIndex] != "" {
			name = append(name, match[busNumIndex])
		}
		if diskIndex != -1 && match[diskIndex] != "" {
			name = append(name, match[diskIndex])
		}

		return strings.Join(name, "_")
	}
	return ""
}

// NewSMARTctl is smartctl constructor
func NewSMARTctl(logger log.Logger, json gjson.Result, ch chan<- prometheus.Metric) SMARTctl {
	var model_name string
	if obj := json.Get("model_name"); obj.Exists() {
		model_name = obj.String()
	} else if obj := json.Get("scsi_model_name"); obj.Exists() {
		model_name = obj.String()
	}
	// If the drive returns an empty model name, replace that with unknown.
	if model_name == "" {
		model_name = "unknown"
	}

	return SMARTctl{
		ch:     ch,
		json:   json,
		logger: logger,
		device: SMARTDevice{
			device:     extractDiskName(strings.TrimSpace(json.Get("device.info_name").String())),
			serial:     strings.TrimSpace(json.Get("serial_number").String()),
			family:     strings.TrimSpace(GetStringIfExists(json, "model_family", "unknown")),
			model:      strings.TrimSpace(model_name),
			interface_: strings.TrimSpace(json.Get("device.type").String()),
			protocol:   strings.TrimSpace(json.Get("device.protocol").String()),
		},
	}
}

// Collect metrics
func (smart *SMARTctl) Collect() {
	level.Debug(smart.logger).Log("msg", "Collecting metrics from", "device", smart.device.device, "family", smart.device.family, "model", smart.device.model)
	smart.mineExitStatus()
	smart.mineDevice()
	smart.mineCapacity()
	smart.mineBlockSize()
	smart.mineInterfaceSpeed()
	smart.mineDeviceAttribute()
	smart.minePowerOnSeconds()
	smart.mineRotationRate()
	smart.mineTemperatures()
	smart.minePowerCycleCount() // ATA/SATA, NVME, SCSI, SAS
	smart.mineDeviceSCTStatus()
	smart.mineDeviceStatistics()
	smart.mineDeviceErrorLog()
	smart.mineDeviceSelfTestLog()
	smart.mineDeviceERC()
	smart.mineSmartStatus()

	if smart.device.interface_ == "nvme" {
		smart.mineNvmePercentageUsed()
		smart.mineNvmeAvailableSpare()
		smart.mineNvmeAvailableSpareThreshold()
		smart.mineNvmeCriticalWarning()
		smart.mineNvmeMediaErrors()
		smart.mineNvmeNumErrLogEntries()
		smart.mineNvmeBytesRead()
		smart.mineNvmeBytesWritten()
		smart.mineNvmeCriticalCompTime()
		smart.mineNvmeWarningTempTime()
	}
	// SCSI, SAS
	if smart.device.interface_ == "scsi" {
		smart.mineSCSIGrownDefectList()
		smart.mineSCSIErrorCounterLog()
		smart.mineSCSIBytesRead()
		smart.mineSCSIBytesWritten()
	}
}

func (smart *SMARTctl) mineExitStatus() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceExitStatus,
		prometheus.GaugeValue,
		smart.json.Get("smartctl.exit_status").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineDevice() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceModel,
		prometheus.GaugeValue,
		1,
		smart.device.device,
		smart.device.interface_,
		smart.device.protocol,
		smart.device.family,
		smart.device.model,
		smart.device.serial,
		GetStringIfExists(smart.json, "ata_additional_product_id", "unknown"),
		smart.json.Get("firmware_version").String(),
		smart.json.Get("ata_version.string").String(),
		smart.json.Get("sata_version.string").String(),
		smart.json.Get("form_factor.name").String(),
		// scsi_model_name is mapped into model_name
		smart.json.Get("scsi_vendor").String(),
		smart.json.Get("scsi_product").String(),
		smart.json.Get("scsi_revision").String(),
		smart.json.Get("scsi_version").String(),
	)
}

func (smart *SMARTctl) mineCapacity() {
	// The user_capacity exists only when NVMe have single namespace. Otherwise,
	// for NVMe devices with multiple namespaces, when device name used without
	// namespace number (exporter case) user_capacity will be absent
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCapacityBlocks,
		prometheus.GaugeValue,
		smart.json.Get("user_capacity.blocks").Float(),
		smart.device.device,
	)
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCapacityBytes,
		prometheus.GaugeValue,
		smart.json.Get("user_capacity.bytes").Float(),
		smart.device.device,
	)
	nvme_total_capacity := smart.json.Get("nvme_total_capacity")
	if nvme_total_capacity.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceTotalCapacityBytes,
			prometheus.GaugeValue,
			nvme_total_capacity.Float(),
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineBlockSize() {
	for _, blockType := range []string{"logical", "physical"} {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBlockSize,
			prometheus.GaugeValue,
			smart.json.Get(fmt.Sprintf("%s_block_size", blockType)).Float(),
			smart.device.device,
			blockType,
		)
	}
}

func (smart *SMARTctl) mineInterfaceSpeed() {
	// TODO: Support scsi_sas_port_[01].phy_N.negotiated_logical_link_rate
	iSpeed := smart.json.Get("interface_speed")
	if iSpeed.Exists() {
		for _, speedType := range []string{"max", "current"} {
			tSpeed := iSpeed.Get(speedType)
			if tSpeed.Exists() {
				smart.ch <- prometheus.MustNewConstMetric(
					metricDeviceInterfaceSpeed,
					prometheus.GaugeValue,
					tSpeed.Get("units_per_second").Float()*tSpeed.Get("bits_per_unit").Float(),
					smart.device.device,
					speedType,
				)
			}
		}
	}
}

func (smart *SMARTctl) mineDeviceAttribute() {
	for _, attribute := range smart.json.Get("ata_smart_attributes.table").Array() {
		name := strings.TrimSpace(attribute.Get("name").String())
		flagsShort := strings.TrimSpace(attribute.Get("flags.string").String())
		flagsLong := smart.mineLongFlags(attribute.Get("flags"), []string{
			"prefailure",
			"updated_online",
			"performance",
			"error_rate",
			"event_count",
			"auto_keep",
		})
		id := attribute.Get("id").String()
		for key, path := range map[string]string{
			"value":  "value",
			"worst":  "worst",
			"thresh": "thresh",
			"raw":    "raw.value",
		} {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceAttribute,
				prometheus.GaugeValue,
				attribute.Get(path).Float(),
				smart.device.device,
				name,
				flagsShort,
				flagsLong,
				key,
				id,
			)
		}
	}
}

func (smart *SMARTctl) minePowerOnSeconds() {
	pot := smart.json.Get("power_on_time")
	// If the power_on_time is NOT present, do not report as 0.
	if pot.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerOnSeconds,
			prometheus.CounterValue,
			GetFloatIfExists(pot, "hours", 0)*60*60+GetFloatIfExists(pot, "minutes", 0)*60,
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineRotationRate() {
	rRate := GetFloatIfExists(smart.json, "rotation_rate", 0)
	// TODO: what should be done if this is absent vs really zero (for
	// solid-state drives)?
	if rRate > 0 {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceRotationRate,
			prometheus.GaugeValue,
			rRate,
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineTemperatures() {
	temperatures := smart.json.Get("temperature")
	// TODO: Implement scsi_environmental_reports
	if temperatures.Exists() {
		temperatures.ForEach(func(key, value gjson.Result) bool {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceTemperature,
				prometheus.GaugeValue,
				value.Float(),
				smart.device.device,
				key.String(),
			)
			return true
		})
	}
}

func (smart *SMARTctl) minePowerCycleCount() {
	// ATA & NVME
	powerCycleCount := smart.json.Get("power_cycle_count")
	if powerCycleCount.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerCycleCount,
			prometheus.CounterValue,
			powerCycleCount.Float(),
			smart.device.device,
		)
		return
	}

	// SCSI
	powerCycleCount = smart.json.Get("scsi_start_stop_cycle_counter.accumulated_start_stop_cycles")
	if powerCycleCount.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerCycleCount,
			prometheus.CounterValue,
			powerCycleCount.Float(),
			smart.device.device,
		)
		return
	}
}

func (smart *SMARTctl) mineDeviceSCTStatus() {
	status := smart.json.Get("ata_sct_status")
	if status.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceState,
			prometheus.GaugeValue,
			status.Get("device_state").Float(),
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineNvmePercentageUsed() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDevicePercentageUsed,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.percentage_used").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeAvailableSpare() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpare,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeAvailableSpareThreshold() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpareThreshold,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare_threshold").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeCriticalWarning() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCriticalWarning,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.critical_warning").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeWarningTempTime() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceWarningTempTime,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.warning_temp_time").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeCriticalCompTime() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCriticalCompTime,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.critical_comp_time").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeMediaErrors() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceMediaErrors,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.media_errors").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeNumErrLogEntries() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceNumErrLogEntries,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.num_err_log_entries").Float(),
		smart.device.device,
	)
}

// https://nvmexpress.org/wp-content/uploads/NVM-Express-NVM-Command-Set-Specification-1.0d-2023.12.28-Ratified.pdf
// 4.1.4.2 SMART / Health Information (02h)
// The SMART / Health Information log page is as defined in the NVM Express Base Specification. For the
// Data Units Read and Data Units Written fields, when the logical block size is a value other than 512 bytes,
// the controller shall convert the amount of data read to 512 byte units.

// https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf
// Figure 208: SMART / Health Information Log Page
// Bytes 47:32
// Data Units Read: Contains the number of 512 byte data units the host has read from the
// controller as part of processing a SMART Data Units Read Command; this value does not
// include metadata. This value is reported in thousands (i.e., a value of 1 corresponds to 1,000
// units of 512 bytes read) and is rounded up (e.g., one indicates that the number of 512 byte
// data units read is from 1 to 1,000, three indicates that the number of 512 byte data units read
// is from 2,001 to 3,000).
//
// A value of 0h in this field indicates that the number of SMART Data Units Read is not reported.
//
// Bytes 63:48
//
// Data Units Written: Contains the number of 512 byte data units the host has written to the ...
// (the same as Data Units Read)

func (smart *SMARTctl) mineNvmeBytesRead() {
	data_units_read := smart.json.Get("nvme_smart_health_information_log.data_units_read")
	// 0 => not reported by underlying hardware
	if !data_units_read.Exists() || data_units_read.Int() == 0 {
		return
	}
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesRead,
		prometheus.CounterValue,
		// WARNING: Float64 will lose precision when drives reach ~32EiB read/write
		// The underlying data_units_written,data_units_read are 128-bit integers
		data_units_read.Float()*1000.0*512.0,
		smart.device.device,
	)
}

func (smart *SMARTctl) mineNvmeBytesWritten() {
	data_units_written := smart.json.Get("nvme_smart_health_information_log.data_units_written")
	// 0 => not reported by underlying hardware
	if !data_units_written.Exists() || data_units_written.Int() == 0 {
		return
	}
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesWritten,
		prometheus.CounterValue,
		// WARNING: Float64 will lose precision when drives reach ~32EiB read/write
		// The underlying data_units_written,data_units_read are 128-bit integers
		data_units_written.Float()*1000.0*512.0,
		smart.device.device,
	)
}

func (smart *SMARTctl) mineSCSIBytesRead() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBytesRead,
			prometheus.CounterValue,
			// This value is reported by SMARTctl in GB [10^9].
			// It is possible that some drives mis-report the value, but
			// that is not the responsibility of the exporter or smartctl
			SCSIHealth.Get("read.gigabytes_processed").Float()*1e9,
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineSCSIBytesWritten() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBytesWritten,
			prometheus.CounterValue,
			// This value is reported by SMARTctl in GB [10^9].
			// It is possible that some drives mis-report the value, but
			// that is not the responsibility of the exporter or smartctl
			SCSIHealth.Get("write.gigabytes_processed").Float()*1e9,
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineSmartStatus() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceSmartStatus,
		prometheus.GaugeValue,
		smart.json.Get("smart_status.passed").Float(),
		smart.device.device,
	)
}

func (smart *SMARTctl) mineDeviceStatistics() {
	for _, page := range smart.json.Get("ata_device_statistics.pages").Array() {
		table := strings.TrimSpace(page.Get("name").String())
		// skip vendor-specific statistics (they lead to duplicate metric labels on Seagate Exos drives,
		// see https://github.com/Sheridan/smartctl_exporter/issues/3 for details)
		if table == "Vendor Specific Statistics" {
			continue
		}
		for _, statistic := range page.Get("table").Array() {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceStatistics,
				prometheus.GaugeValue,
				statistic.Get("value").Float(),
				smart.device.device,
				table,
				strings.TrimSpace(statistic.Get("name").String()),
				strings.TrimSpace(statistic.Get("flags.string").String()),
				smart.mineLongFlags(statistic.Get("flags"), []string{
					"valid",
					"normalized",
					"supports_dsn",
					"monitored_condition_met",
				}),
			)
		}
	}

	for _, statistic := range smart.json.Get("sata_phy_event_counters.table").Array() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceStatistics,
			prometheus.GaugeValue,
			statistic.Get("value").Float(),
			smart.device.device,
			"SATA PHY Event Counters",
			strings.TrimSpace(statistic.Get("name").String()),
			"V---",
			"valid",
		)
	}
}

func (smart *SMARTctl) mineLongFlags(json gjson.Result, flags []string) string {
	var result []string
	for _, flag := range flags {
		jFlag := json.Get(flag)
		if jFlag.Exists() && jFlag.Bool() {
			result = append(result, flag)
		}
	}
	return strings.Join(result, ",")
}

func (smart *SMARTctl) mineDeviceErrorLog() {
	for logType, status := range smart.json.Get("ata_smart_error_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceErrorLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceSelfTestLog() {
	for logType, status := range smart.json.Get("ata_smart_self_test_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			logType,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogErrorCount,
			prometheus.GaugeValue,
			status.Get("error_count_total").Float(),
			smart.device.device,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceERC() {
	for ercType, status := range smart.json.Get("ata_sct_erc").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceERCSeconds,
			prometheus.GaugeValue,
			status.Get("deciseconds").Float()/10.0,
			smart.device.device,
			ercType,
		)
	}
}

func (smart *SMARTctl) mineSCSIGrownDefectList() {
	scsi_grown_defect_list := smart.json.Get("scsi_grown_defect_list")
	if scsi_grown_defect_list.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIGrownDefectList,
			prometheus.GaugeValue,
			scsi_grown_defect_list.Float(),
			smart.device.device,
		)
	}
}

func (smart *SMARTctl) mineSCSIErrorCounterLog() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByRereadsRewrites,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_rereads_rewrites").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByEccFast,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_eccfast").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByEccDelayed,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_eccdelayed").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadTotalUncorrectedErrors,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.total_uncorrected_errors").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByRereadsRewrites,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_rereads_rewrites").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByEccFast,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_eccfast").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByEccDelayed,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_eccdelayed").Float(),
			smart.device.device,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteTotalUncorrectedErrors,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.total_uncorrected_errors").Float(),
			smart.device.device,
		)
		// TODO: Should we also export the verify category?
	}
}

func GetStringIfExists(json gjson.Result, key string, def string) string {
	value := json.Get(key)
	if value.Exists() {
		return value.String()
	}
	return def
}

// GetFloatIfExists returns json value or default
func GetFloatIfExists(json gjson.Result, key string, def float64) float64 {
	value := json.Get(key)
	if value.Exists() {
		return value.Float()
	}
	return def
}

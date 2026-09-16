package host

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Snapshot struct {
	CPU     CPU    `json:"cpu"`
	Memory  Memory `json:"memory"`
	UptimeS uint64 `json:"uptime_s"`
}

type CPU struct {
	Cores  int     `json:"cores"`
	Usage  float64 `json:"usage"`
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type Memory struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
}

var prevIdle, prevTotal uint64

func Hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func Collect() Snapshot {
	s := Snapshot{}
	s.CPU.Cores = runtime.NumCPU()
	s.UptimeS = readUptime()
	s.CPU.Load1, s.CPU.Load5, s.CPU.Load15 = readLoad()
	s.CPU.Usage = readCPUUsage()
	s.Memory.Total, s.Memory.Available = readMem()
	if s.Memory.Total > s.Memory.Available {
		s.Memory.Used = s.Memory.Total - s.Memory.Available
	}
	return s
}

func readUptime() uint64 {
	fields := fieldsOf("/proc/uptime")
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(v)
}

func readLoad() (float64, float64, float64) {
	fields := fieldsOf("/proc/loadavg")
	if len(fields) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(fields[0], 64)
	b, _ := strconv.ParseFloat(fields[1], 64)
	c, _ := strconv.ParseFloat(fields[2], 64)
	return a, b, c
}

func readCPUUsage() float64 {
	idle, total := cpuTicks()
	if prevTotal == 0 {
		prevIdle, prevTotal = idle, total
		return 0
	}
	idleD := idle - prevIdle
	totalD := total - prevTotal
	prevIdle, prevTotal = idle, total
	if totalD == 0 {
		return 0
	}
	return 1 - float64(idleD)/float64(totalD)
}

func cpuTicks() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var sum uint64
	for i, f := range fields[1:] {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			continue
		}
		sum += n
		if i == 3 {
			idle = n
		}
	}
	return idle, sum
}

func readMem() (total, available uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		n *= 1024
		switch key {
		case "MemTotal":
			total = n
		case "MemAvailable":
			available = n
		}
	}
	return total, available
}

func fieldsOf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

package main

import (
 "bytes"
 "encoding/json"
 "encoding/xml"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strings"
 "time"
)

type Config struct {
 Networks []NetworkConfig `json:"networks"`
 Scan     ScanConfig      `json:"scan"`
}

type NetworkConfig struct {
 Name    string `json:"name"`
 CIDR    string `json:"cidr"`
 Enabled bool   `json:"enabled"`
}

type ScanConfig struct {
 DiscoveryXML     string `json:"discovery_xml"`
 DetailXML        string `json:"detail_xml"`
 OutputHTML       string `json:"output_html"`
 TopPorts         int    `json:"top_ports"`
 Timing           string `json:"timing"`
 MaxRetries       int    `json:"max_retries"`
 ServiceDetection bool   `json:"service_detection"`
 OSDetection      bool   `json:"os_detection"`
}

type NmapRun struct {
 XMLName xml.Name   `xml:"nmaprun"`
 Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
 Status    HostStatus `xml:"status"`
 Addresses []Address  `xml:"address"`
}

type HostStatus struct {
 State  string `xml:"state,attr"`
 Reason string `xml:"reason,attr"`
}

type Address struct {
 Addr     string `xml:"addr,attr"`
 AddrType string `xml:"addrtype,attr"`
}

func main() {
 if len(os.Args) < 2 {
  fmt.Println("usage: ./skaner <config.json>")
  os.Exit(1)
 }

 cfg, err := loadConfig(os.Args[1])
 if err != nil {
  fmt.Println("config error:", err)
  os.Exit(1)
 }

 networks := enabledNetworks(cfg.Networks)
 if len(networks) == 0 {
  fmt.Println("no enabled networks in config")
  os.Exit(1)
 }

 for _, network := range networks {
  logStep("network", fmt.Sprintf("processing %s (%s)", network.Name, network.CIDR))

  if err := runDiscovery(network.CIDR, cfg.Scan.DiscoveryXML); err != nil {
   fmt.Println("discovery error:", err)
   os.Exit(1)
  }

  hosts, err := parseAliveHosts(cfg.Scan.DiscoveryXML)
  if err != nil {
   fmt.Println("parse discovery error:", err)
   os.Exit(1)
  }

  logStep("discovery", fmt.Sprintf("alive hosts found: %d", len(hosts)))
  if len(hosts) == 0 {
   logStep("detail", "skip detail scan, no alive hosts")
   continue
  }

  if err := runDetailScan(hosts, cfg.Scan); err != nil {
   fmt.Println("detail scan error:", err)
   os.Exit(1)
  }

  logStep("done", fmt.Sprintf("detail xml written to %s", cfg.Scan.DetailXML))
 }
}

func logStep(stage, message string) {
 fmt.Printf("[%s] %-12s %s\n", time.Now().Format("15:04:05"), stage, message)
}

func loadConfig(path string) (Config, error) {
 var cfg Config

 data, err := os.ReadFile(path)
 if err != nil {
  return cfg, err
 }

 if err := json.Unmarshal(data, &cfg); err != nil {
  return cfg, err
 }

 if cfg.Scan.DiscoveryXML == "" {
  cfg.Scan.DiscoveryXML = "discovery.xml"
 }
 if cfg.Scan.DetailXML == "" {
  cfg.Scan.DetailXML = "scan.xml"
 }
 if cfg.Scan.TopPorts <= 0 {
  cfg.Scan.TopPorts = 1000
 }
 if cfg.Scan.Timing == "" {
  cfg.Scan.Timing = "T4"
 }
 if cfg.Scan.MaxRetries < 0 {
  return cfg, errors.New("max_retries cannot be negative")
 }

 return cfg, nil
}

func enabledNetworks(items []NetworkConfig) []NetworkConfig {
 result := make([]NetworkConfig, 0)
 for _, n := range items {
  if !n.Enabled {
   continue
  }
  if strings.TrimSpace(n.CIDR) == "" {
   continue
  }
  result = append(result, n)
 }
 return result
}

func runDiscovery(cidr, outXML string) error {
 args := []string{
  "-sn",
  "-n",
  "-oX", outXML,
  cidr,
 }

 logStep("discovery", "nmap "+strings.Join(args, " "))
 return runCommand("nmap", args...)
}

func parseAliveHosts(path string) ([]string, error) {
 data, err := os.ReadFile(path)
 if err != nil {
  return nil, err
 }

 var run NmapRun
 if err := xml.Unmarshal(data, &run); err != nil {
  return nil, err
 }

 hosts := make([]string, 0)
 for _, host := range run.Hosts {
  if host.Status.State != "up" {
   continue
  }
  ip := pickIPv4(host.Addresses)
  if ip == "" {
   continue
  }
  hosts = append(hosts, ip)
 }

 return hosts, nil
}

func pickIPv4(addrs []Address) string {
 for _, a := range addrs {
  if a.AddrType == "ipv4" {
   return a.Addr
  }
 }
 return ""
}

func runDetailScan(hosts []string, scan ScanConfig) error {
 args := []string{
  "-oX", scan.DetailXML,
  "-Pn",
  "-n",
  "-sS",
 }

 if scan.ServiceDetection {
  args = append(args, "-sV", "--version-light")
 }
 if scan.OSDetection {
  args = append(args, "-O", "--osscan-limit")
 }

 args = append(args,
  "--top-ports", fmt.Sprintf("%d", scan.TopPorts),
  "-"+scan.Timing,
  "--max-retries", fmt.Sprintf("%d", scan.MaxRetries),
 )

 args = append(args, hosts...)

 logStep("detail", "nmap "+strings.Join(args, " "))
 return runCommand("nmap", args...)
}

func runCommand(name string, args ...string) error {
 cmd := exec.Command(name, args...)

 var stdout bytes.Buffer
 var stderr bytes.Buffer
 cmd.Stdout = &stdout
 cmd.Stderr = &stderr

 err := cmd.Run()

 out := strings.TrimSpace(stdout.String())
 if out != "" {
  fmt.Println(out)
 }

 errOut := strings.TrimSpace(stderr.String())
 if errOut != "" {
  fmt.Println(errOut)
 }

 return err
}
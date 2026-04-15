package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Config struct {
	ScanEnabled bool            `json:"scan_enabled"`
	Scan        ScanSettings    `json:"scan"`
	Networks    []NetworkConfig `json:"networks"`
}

type ScanSettings struct {
	DiscoveryEnabled bool   `json:"discovery_enabled"`
	TopPorts         int    `json:"top_ports"`
	Timing           string `json:"timing"`
	MaxRetries       int    `json:"max_retries"`
	ServiceDetection bool   `json:"service_detection"`
	OSDetection      bool   `json:"os_detection"`
	VersionIntensity string `json:"version_intensity"`
}

type NetworkConfig struct {
	Name           string   `json:"name"`
	CIDR           string   `json:"cidr"`
	DiscoveryXML   string   `json:"discovery_xml"`
	XMLInput       string   `json:"xml_input"`
	HTMLOutput     string   `json:"html_output"`
	Enabled        bool     `json:"enabled"`
}

type NmapRun struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Scanner  string     `xml:"scanner,attr"`
	Args     string     `xml:"args,attr"`
	StartStr string     `xml:"startstr,attr"`
	Version  string     `xml:"version,attr"`
	Hosts    []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames NmapHostnames `xml:"hostnames"`
	Ports     NmapPorts     `xml:"ports"`
	OS        NmapOS        `xml:"os"`
}

type NmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type NmapHostnames struct {
	Hostnames []NmapHostname `xml:"hostname"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    NmapPortState `xml:"state"`
	Service  NmapService   `xml:"service"`
	Scripts  []NmapScript  `xml:"script"`
}

type NmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
}

type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapOS struct {
	Matches []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type Report struct {
	GeneratedAt   string       `json:"generated_at"`
	NetworkName   string       `json:"network_name"`
	CIDR          string       `json:"cidr"`
	SourceXML     string       `json:"source_xml"`
	Scanner       string       `json:"scanner"`
	ScannerVer    string       `json:"scanner_version"`
	ScannerArgs   string       `json:"scanner_args"`
	HostCount     int          `json:"host_count"`
	OpenPortCount int          `json:"open_port_count"`
	Hosts         []HostReport `json:"hosts"`
}

type HostReport struct {
	IP        string       `json:"ip"`
	Hostname  string       `json:"hostname"`
	MAC       string       `json:"mac"`
	MACVendor string       `json:"mac_vendor"`
	Status    string       `json:"status"`
	OS        []string     `json:"os"`
	Tags      []string     `json:"tags"`
	Ports     []PortReport `json:"ports"`

	SMB *SMBResult `json:"smb,omitempty"`
	NFS *NFSResult `json:"nfs,omitempty"`
	RPC string     `json:"rpc,omitempty"`
}

type PortReport struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Service   string `json:"service"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	ExtraInfo string `json:"extra_info"`
	Tunnel    string `json:"tunnel"`
}

type SMBResult struct {
	Shares []string `json:"shares"`
	Users  []string `json:"users"`
	Raw    string   `json:"raw"`
}

type NFSResult struct {
	Exports []string `json:"exports"`
	Raw     string   `json:"raw"`
}

type HTMLTemplateData struct {
	CSS      template.CSS
	JSONData template.JS
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
		fmt.Println("no enabled networks found in config")
		os.Exit(1)
	}

	if cfg.ScanEnabled {
		logStep("startup", "scan_enabled=true, scan + html mode")
	} else {
		logStep("startup", "scan_enabled=false, html from existing xml mode")
	}

	for _, network := range networks {
		logStep("network", fmt.Sprintf("processing %s (%s)", network.Name, network.CIDR))

		if cfg.ScanEnabled {
			if err := scanNetwork(network, cfg.Scan); err != nil {
				fmt.Printf("scan error for %s: %v\n", network.Name, err)
				os.Exit(1)
			}
		}

		run, err := parseNmapXML(network.XMLInput)
		if err != nil {
			fmt.Printf("xml parse error for %s: %v\n", network.Name, err)
			os.Exit(1)
		}

		report := buildReport(network, run)

		logStep("enum", "auto-detecting additional file-service scans")
		enrichReport(&report, network)

		logStep("report", fmt.Sprintf(
			"network=%s hosts=%d open_ports=%d output=%s",
			network.Name,
			report.HostCount,
			report.OpenPortCount,
			network.HTMLOutput,
		))

		if err := writeHTMLReport(network.HTMLOutput, report); err != nil {
			fmt.Printf("html error for %s: %v\n", network.Name, err)
			os.Exit(1)
		}
	}

	logStep("done", "all reports generated")
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

	if cfg.Scan.TopPorts <= 0 {
		cfg.Scan.TopPorts = 1000
	}
	if cfg.Scan.Timing == "" {
		cfg.Scan.Timing = "T4"
	}
	if cfg.Scan.VersionIntensity == "" {
		cfg.Scan.VersionIntensity = "light"
	}
	if cfg.Scan.MaxRetries < 0 {
		return cfg, errors.New("max_retries cannot be negative")
	}

	return cfg, nil
}

func enabledNetworks(items []NetworkConfig) []NetworkConfig {
	result := make([]NetworkConfig, 0)
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if strings.TrimSpace(item.XMLInput) == "" {
			continue
		}
		if strings.TrimSpace(item.HTMLOutput) == "" {
			item.HTMLOutput = item.Name + ".html"
		}
		if strings.TrimSpace(item.DiscoveryXML) == "" {
			item.DiscoveryXML = item.Name + "-discovery.xml"
		}
		result = append(result, item)
	}
	return result
}

func scanNetwork(network NetworkConfig, scan ScanSettings) error {
	if strings.TrimSpace(network.CIDR) == "" {
		return fmt.Errorf("network %s has empty cidr", network.Name)
	}

	if scan.DiscoveryEnabled {
		logStep("discovery", fmt.Sprintf("running host discovery for %s", network.Name))
		hosts, err := runDiscoveryAndCollectHosts(network)
		if err != nil {
			return err
		}

		logStep("discovery", fmt.Sprintf("alive hosts found: %d", len(hosts)))
		if len(hosts) == 0 {
			logStep("detail", "skip detail scan, no alive hosts")
			return createEmptyNmapXML(network.XMLInput)
		}

		logStep("detail", fmt.Sprintf("running detail scan for %d host(s)", len(hosts)))
		return runDetailScan(hosts, network.XMLInput, scan)
	}

	logStep("detail", "discovery disabled, running detail scan on whole cidr")
	return runDetailScan([]string{network.CIDR}, network.XMLInput, scan)
}

func runDiscoveryAndCollectHosts(network NetworkConfig) ([]string, error) {
	args := []string{
		"-sn",
		"-n",
		"-oX", network.DiscoveryXML,
		network.CIDR,
	}

	logStep("discovery", "nmap "+strings.Join(args, " "))
	if err := runCommand("nmap", args...); err != nil {
		return nil, err
	}

	run, err := parseNmapXML(network.DiscoveryXML)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0)
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}
		ip := pickIPv4(host.Addresses)
		if ip == "" {
			ip = pickAnyAddress(host.Addresses)
		}
		if ip == "" {
			continue
		}
		hosts = append(hosts, ip)
	}

	return uniqueStrings(hosts), nil
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func runDetailScan(targets []string, outXML string, scan ScanSettings) error {
	args := []string{
		"-oX", outXML,
		"-Pn",
		"-n",
		"-sS",
	}

	if scan.ServiceDetection {
		args = append(args, "-sV")
		if strings.EqualFold(scan.VersionIntensity, "light") {
			args = append(args, "--version-light")
		}
	}

	if scan.OSDetection {
		args = append(args, "-O", "--osscan-limit")
	}

	args = append(args,
		"--top-ports", fmt.Sprintf("%d", scan.TopPorts),
		"-"+scan.Timing,
		"--max-retries", fmt.Sprintf("%d", scan.MaxRetries),
	)

	args = append(args, targets...)

	logStep("detail", "nmap "+strings.Join(args, " "))
	return runCommand("nmap", args...)
}

func createEmptyNmapXML(path string) error {
	content := `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="" startstr="" version="">
</nmaprun>`
	return os.WriteFile(path, []byte(content), 0644)
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

func runCommandCapture(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())

	if out != "" && errOut != "" {
		return out + "\n\n" + errOut, err
	}
	if out != "" {
		return out, err
	}
	return errOut, err
}

func parseNmapXML(path string) (NmapRun, error) {
	var run NmapRun

	data, err := os.ReadFile(path)
	if err != nil {
		return run, err
	}

	if err := xml.Unmarshal(data, &run); err != nil {
		return run, err
	}

	return run, nil
}

func buildReport(network NetworkConfig, run NmapRun) Report {
	report := Report{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		NetworkName: network.Name,
		CIDR:        network.CIDR,
		SourceXML:   network.XMLInput,
		Scanner:     run.Scanner,
		ScannerVer:  run.Version,
		ScannerArgs: run.Args,
		Hosts:       make([]HostReport, 0),
	}

	for _, host := range run.Hosts {
		if host.Status.State != "" && host.Status.State != "up" {
			continue
		}

		ip := pickIPv4(host.Addresses)
		if ip == "" {
			ip = pickAnyAddress(host.Addresses)
		}
		if ip == "" {
			continue
		}

		openPorts := make([]PortReport, 0)
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			openPorts = append(openPorts, PortReport{
				Port:      port.PortID,
				Protocol:  port.Protocol,
				Service:   port.Service.Name,
				Product:   port.Service.Product,
				Version:   port.Service.Version,
				ExtraInfo: port.Service.ExtraInfo,
				Tunnel:    port.Service.Tunnel,
			})
		}

		if len(openPorts) == 0 {
			continue
		}

		sort.Slice(openPorts, func(i, j int) bool {
			if openPorts[i].Port == openPorts[j].Port {
				return openPorts[i].Protocol < openPorts[j].Protocol
			}
			return openPorts[i].Port < openPorts[j].Port
		})

		report.Hosts = append(report.Hosts, HostReport{
			IP:        ip,
			Hostname:  pickHostname(host.Hostnames, ip),
			MAC:       pickMAC(host.Addresses),
			MACVendor: pickMACVendor(host.Addresses),
			Status:    host.Status.State,
			OS:        collectOSMatches(host.OS),
			Tags:      buildHostTags(openPorts),
			Ports:     openPorts,
		})
	}

	sort.Slice(report.Hosts, func(i, j int) bool {
		return compareIPStrings(report.Hosts[i].IP, report.Hosts[j].IP)
	})

	report.HostCount = len(report.Hosts)

	openPortCount := 0
	for _, host := range report.Hosts {
		openPortCount += len(host.Ports)
	}
	report.OpenPortCount = openPortCount

	return report
}

func enrichReport(report *Report, network NetworkConfig) {
	for i := range report.Hosts {
		host := &report.Hosts[i]
		if hostHasPort(host, 139) || hostHasPort(host, 445) {
			logStep("enum", "SMB detected on "+host.IP)
			smb, err := runSMBEnum(host.IP)
			if err == nil && smb != nil {
				host.SMB = smb
			}
		}
		if hostHasPort(host, 111) || hostHasPort(host, 2049) {
			logStep("enum", "NFS detected on "+host.IP)
			rpc, err := runRPCEnum(host.IP)
			if err == nil {
				host.RPC = rpc
			}
			nfs, err := runNFSEnum(host.IP)
			if err == nil && nfs != nil {
				host.NFS = nfs
			}
		}
	}
}

func runSMBEnum(ip string) (*SMBResult, error) {
 result := &SMBResult{}

 nmapOut, _ := runCommandCapture(
  "nmap",
  "-Pn",
  "-n",
  "-p", "139,445",
  "--script",
  "smb-enum-shares,smb-enum-users,smb-os-discovery",
  ip,
 )

 result.Raw += "\n=== NMAP ===\n" + nmapOut

 smbOut, _ := runCommandCapture(
  "smbclient",
  "-L", "//"+ip+"/",
  "-N",
 )

 result.Raw += "\n=== SMBCLIENT ===\n" + smbOut

 for _, line := range strings.Split(smbOut, "\n") {
  line = strings.TrimSpace(line)

  if strings.Contains(line, "Disk") || strings.Contains(line, "IPC") {
   fields := strings.Fields(line)
   if len(fields) > 0 {
    result.Shares = append(result.Shares, fields[0])
   }
  }
 }

 rpcOut, _ := runCommandCapture(
  "rpcclient",
  "-U", "",
  "-N",
  ip,
  "-c", "enumdomusers",
 )

 result.Raw += "\n=== RPCCLIENT ===\n" + rpcOut

 for _, line := range strings.Split(rpcOut, "\n") {
  if strings.Contains(line, "user:") {
   result.Users = append(result.Users, line)
  }
 }

 result.Shares = uniqueStrings(result.Shares)
 result.Users = uniqueStrings(result.Users)

 return result, nil
}

func runNFSEnum(ip string) (*NFSResult, error) {
	out, err := runCommandCapture("showmount", "-e", ip)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err
	}

	return &NFSResult{
		Exports: parseNFSExports(out),
		Raw:     out,
	}, nil
}

func parseSMBShares(text string) []string {
	lines := strings.Split(text, "\n")
	seen := make(map[string]struct{})
	result := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, "|_ "))
		if !strings.HasPrefix(line, `\\`) {
			continue
		}

		lastSlash := strings.LastIndex(line, `\`)
		if lastSlash < 0 || lastSlash+1 >= len(line) {
			continue
		}

		share := strings.TrimSpace(strings.TrimSuffix(line[lastSlash+1:], ":"))
		if share == "" {
			continue
		}

		if _, ok := seen[share]; ok {
			continue
		}
		seen[share] = struct{}{}
		result = append(result, share)
	}

	sort.Strings(result)
	return result
}

func parseSMBUsers(text string) []string {
	lines := strings.Split(text, "\n")
	seen := make(map[string]struct{})
	result := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, "|_ "))
		if strings.HasPrefix(line, `\\`) {
			continue
		}
		if !strings.Contains(line, `\`) {
			continue
		}

		fields := strings.Fields(line)
		for _, field := range fields {
			if !strings.Contains(field, `\`) {
				continue
			}

			user := strings.Trim(field, "(),")
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}

			if _, ok := seen[user]; ok {
				continue
			}
			seen[user] = struct{}{}
			result = append(result, user)
		}
	}

	sort.Strings(result)
	return result
}

func parseNFSExports(text string) []string {
	lines := strings.Split(text, "\n")
	seen := make(map[string]struct{})
	result := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "export list") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		exportPath := fields[0]
		if !strings.HasPrefix(exportPath, "/") {
			continue
		}

		if _, ok := seen[exportPath]; ok {
			continue
		}
		seen[exportPath] = struct{}{}
		result = append(result, exportPath)
	}

	sort.Strings(result)
	return result
}

func buildHostTags(ports []PortReport) []string {
	tags := make(map[string]struct{})

	for _, p := range ports {
		service := strings.ToLower(strings.TrimSpace(p.Service))

		switch {
		case p.Port == 80 || p.Port == 443 || service == "http" || service == "https":
			tags["web"] = struct{}{}
		case p.Port == 25 || service == "smtp":
			tags["smtp"] = struct{}{}
		case p.Port == 21 || service == "ftp":
			tags["ftp"] = struct{}{}
			tags["file-storage"] = struct{}{}
		case p.Port == 22 || service == "ssh":
			tags["ssh"] = struct{}{}
		case p.Port == 139 || p.Port == 445 || service == "microsoft-ds" || service == "netbios-ssn":
			tags["smb"] = struct{}{}
			tags["file-storage"] = struct{}{}
		case p.Port == 111 || p.Port == 2049 || service == "nfs":
			tags["nfs"] = struct{}{}
			tags["file-storage"] = struct{}{}
		case p.Port == 1433 || p.Port == 3306 || p.Port == 5432 || p.Port == 1521 ||
			service == "ms-sql-s" || service == "mysql" || service == "postgresql" || service == "oracle":
			tags["sql"] = struct{}{}
		}
	}

	result := make([]string, 0, len(tags))
	for tag := range tags {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func isWhitelisted(ip string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return false
	}

	for _, item := range whitelist {
		if strings.TrimSpace(item) == ip {
			return true
		}
	}
	return false
}

func hostHasPort(host *HostReport, port int) bool {
	for _, p := range host.Ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func pickIPv4(addrs []NmapAddress) string {
	for _, a := range addrs {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	return ""
}

func pickAnyAddress(addrs []NmapAddress) string {
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0].Addr
}

func pickHostname(hostnames NmapHostnames, ip string) string {
	if len(hostnames.Hostnames) > 0 {
		name := strings.TrimSpace(hostnames.Hostnames[0].Name)
		if name != "" {
			return name
		}
	}

	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}

	return ip
}

func pickMAC(addrs []NmapAddress) string {
	for _, a := range addrs {
		if a.AddrType == "mac" {
			return a.Addr
		}
	}
	return ""
}

func pickMACVendor(addrs []NmapAddress) string {
	for _, a := range addrs {
		if a.AddrType == "mac" {
			return a.Vendor
		}
	}
	return ""
}

func collectOSMatches(osinfo NmapOS) []string {
	result := make([]string, 0, len(osinfo.Matches))
	for _, m := range osinfo.Matches {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			continue
		}
		if strings.TrimSpace(m.Accuracy) != "" {
			name = fmt.Sprintf("%s (%s%%)", name, m.Accuracy)
		}
		result = append(result, name)
	}
	return result
}

func compareIPStrings(a, b string) bool {
	ipa := net.ParseIP(a).To4()
	ipb := net.ParseIP(b).To4()
	if ipa == nil || ipb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ipa[i] == ipb[i] {
			continue
		}
		return ipa[i] < ipb[i]
	}
	return false
}

func runRPCEnum(ip string) (string, error) {
	out, err := runCommandCapture(
		"nmap",
		"-Pn",
		"-n",
		"-p", "111",
		"--script", "rpcinfo",
		ip,
	)

	if err != nil && strings.TrimSpace(out) == "" {
		return "", err
	}

	return out, nil
}

func writeHTMLReport(path string, report Report) error {
	baseDir, err := os.Getwd()
	if err != nil {
		return err
	}

	templatePath := filepath.Join(baseDir, "templates", "report.html")
	cssPath := filepath.Join(baseDir, "templates", "style.css")

	cssBytes, err := os.ReadFile(cssPath)
	if err != nil {
		return fmt.Errorf("read css: %w", err)
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		return err
	}

	tplBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("read html template: %w", err)
	}

	tpl, err := template.New("report").Parse(string(tplBytes))
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	data := HTMLTemplateData{
		CSS:      template.CSS(string(cssBytes)),
		JSONData: template.JS(string(jsonData)),
	}

	if err := tpl.Execute(file, data); err != nil {
		return fmt.Errorf("execute html template: %w", err)
	}

	return file.Sync()
}
package main

import (
 "encoding/xml"
 "fmt"
 "os"
)

type NmapRun struct {
 XMLName xml.Name `xml:"nmaprun"`
 Hosts   []Host   `xml:"host"`
}

type Host struct {
 Status    HostStatus    `xml:"status"`
 Addresses []Address     `xml:"address"`
 Hostnames Hostnames     `xml:"hostnames"`
 Ports     Ports         `xml:"ports"`
 OS        OS            `xml:"os"`
}

type HostStatus struct {
 State  string `xml:"state,attr"`
 Reason string `xml:"reason,attr"`
}

type Address struct {
 Addr     string `xml:"addr,attr"`
 AddrType string `xml:"addrtype,attr"`
 Vendor   string `xml:"vendor,attr"`
}

type Hostnames struct {
 Items []Hostname `xml:"hostname"`
}

type Hostname struct {
 Name string `xml:"name,attr"`
 Type string `xml:"type,attr"`
}

type Ports struct {
 Items []Port `xml:"port"`
}

type Port struct {
 Protocol string    `xml:"protocol,attr"`
 PortID   int       `xml:"portid,attr"`
 State    PortState `xml:"state"`
 Service  Service   `xml:"service"`
 Scripts  []Script  `xml:"script"`
}

type PortState struct {
 State  string `xml:"state,attr"`
 Reason string `xml:"reason,attr"`
}

type Service struct {
 Name      string `xml:"name,attr"`
 Product   string `xml:"product,attr"`
 Version   string `xml:"version,attr"`
 ExtraInfo string `xml:"extrainfo,attr"`
 Tunnel    string `xml:"tunnel,attr"`
 Method    string `xml:"method,attr"`
 Conf      string `xml:"conf,attr"`
}

type Script struct {
 ID     string `xml:"id,attr"`
 Output string `xml:"output,attr"`
}

type OS struct {
 Matches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
 Name     string `xml:"name,attr"`
 Accuracy string `xml:"accuracy,attr"`
}

func ParseHostsFromNmapXML(path string) ([]Host, error) {
 data, err := os.ReadFile(path)
 if err != nil {
  return nil, err
 }

 var run NmapRun
 if err := xml.Unmarshal(data, &run); err != nil {
  return nil, err
 }

 return run.Hosts, nil
}

func main() {
 hosts, err := ParseHostsFromNmapXML("scan.xml")
 if err != nil {
  fmt.Println("parse error:", err)
  return
 }

 fmt.Printf("hosts count: %d\n\n", len(hosts))

 for i, host := range hosts {
  fmt.Printf("HOST #%d\n", i+1)
  fmt.Printf("status: %s (%s)\n", host.Status.State, host.Status.Reason)

  for _, addr := range host.Addresses {
   fmt.Printf("address: %s [%s]", addr.Addr, addr.AddrType)
   if addr.Vendor != "" {
    fmt.Printf(" vendor=%s", addr.Vendor)
   }
   fmt.Println()
  }

  for _, hn := range host.Hostnames.Items {
   fmt.Printf("hostname: %s [%s]\n", hn.Name, hn.Type)
  }

  for _, osMatch := range host.OS.Matches {
   fmt.Printf("os: %s (%s%%)\n", osMatch.Name, osMatch.Accuracy)
  }

  for _, port := range host.Ports.Items {
   fmt.Printf(
    "port: %d/%s state=%s service=%s product=%s version=%s\n",
    port.PortID,
    port.Protocol,
    port.State.State,
    port.Service.Name,
    port.Service.Product,
    port.Service.Version,
   )

   for _, script := range port.Scripts {
    fmt.Printf("  script: %s -> %s\n", script.ID, script.Output)
   }
  }

  fmt.Println("-----")
 }
}
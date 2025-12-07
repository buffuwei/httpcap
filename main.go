package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Config struct {
	Interface  string
	SrcFilter  string
	DstFilters []string
	URIFilter  string
	MaxCount   int
}

var (
	capturedCount int
	connMap       = make(map[string]int)
	pendingReqs   = make(map[string]bool)
	mu            sync.Mutex
)

func main() {
	cfg := Config{}
	var dstFilters string
	flag.StringVar(&cfg.Interface, "i", "", "网络接口 (必需)")
	flag.StringVar(&cfg.SrcFilter, "src", "", "源地址过滤 (IP:Port)")
	flag.StringVar(&dstFilters, "dst", "", "目标地址过滤 (IP:Port)，多个值用逗号分隔")
	flag.StringVar(&cfg.URIFilter, "uri", "", "URI 过滤 (包含匹配)")
	flag.IntVar(&cfg.MaxCount, "n", 10, "最大抓包数量")
	list := flag.Bool("l", false, "列出所有网络接口")
	flag.Parse()

	if *list {
		listInterfaces()
		return
	}

	if cfg.Interface == "" {
		fmt.Println("错误: 必须指定网络接口")
		flag.Usage()
		os.Exit(1)
	}

	// 解析 dst 参数
	if dstFilters != "" {
		cfg.DstFilters = strings.Split(dstFilters, ",")
		for i := range cfg.DstFilters {
			cfg.DstFilters[i] = strings.TrimSpace(cfg.DstFilters[i])
		}
	}

	if err := capture(cfg); err != nil {
		log.Fatal(err)
	}
}

func listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("可用网络接口:")
	for _, device := range devices {
		fmt.Printf("  %s", device.Name)
		if device.Description != "" {
			fmt.Printf(" (%s)", device.Description)
		}
		fmt.Println()
		for _, addr := range device.Addresses {
			fmt.Printf("    IP: %s\n", addr.IP)
		}
	}
}

func capture(cfg Config) error {
	handle, err := pcap.OpenLive(cfg.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开接口失败: %v", err)
	}
	defer handle.Close()

	// 构建 BPF 过滤器
	bpfFilter := "tcp"
	if len(cfg.DstFilters) > 0 || cfg.SrcFilter != "" {
		// 如果指定了地址过滤，不限制端口
		bpfFilter = "tcp"
	} else {
		// 否则只抓 80 端口
		bpfFilter = "tcp port 80"
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("设置过滤器失败: %v", err)
	}

	fmt.Printf("开始在 %s 上抓包 (最多 %d 个包)...\n", cfg.Interface, cfg.MaxCount)
	if cfg.SrcFilter != "" {
		fmt.Printf("源地址过滤: %s\n", cfg.SrcFilter)
	}
	if len(cfg.DstFilters) > 0 {
		fmt.Printf("目标地址过滤: %s\n", strings.Join(cfg.DstFilters, ", "))
	}
	if cfg.URIFilter != "" {
		fmt.Printf("URI 过滤: %s\n", cfg.URIFilter)
	}
	fmt.Println("按 Ctrl+C 停止")
	fmt.Println(strings.Repeat("-", 80))

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		mu.Lock()
		count := capturedCount
		mu.Unlock()
		
		if count >= cfg.MaxCount {
			fmt.Printf("\n已达到最大抓包数量 (%d)，停止抓包\n", cfg.MaxCount)
			break
		}

		processPacket(packet, cfg)
	}

	return nil
}

func processPacket(packet gopacket.Packet, cfg Config) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	tcp, ok := transportLayer.(*layers.TCP)
	if !ok {
		return
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	payload := string(appLayer.Payload())
	if !strings.HasPrefix(payload, "GET") && !strings.HasPrefix(payload, "POST") &&
		!strings.HasPrefix(payload, "PUT") && !strings.HasPrefix(payload, "DELETE") &&
		!strings.HasPrefix(payload, "HEAD") && !strings.HasPrefix(payload, "OPTIONS") &&
		!strings.HasPrefix(payload, "PATCH") && !strings.HasPrefix(payload, "HTTP/") {
		return
	}

	src := fmt.Sprintf("%s:%d", networkLayer.NetworkFlow().Src(), tcp.SrcPort)
	dst := fmt.Sprintf("%s:%d", networkLayer.NetworkFlow().Dst(), tcp.DstPort)

	isResponse := strings.HasPrefix(payload, "HTTP/")
	
	// 生成连接标识（客户端IP:Port-服务端IP:Port）
	var connKey string
	if isResponse {
		connKey = fmt.Sprintf("%s-%s", dst, src)
	} else {
		connKey = fmt.Sprintf("%s-%s", src, dst)
	}

	mu.Lock()
	reqNum, exists := connMap[connKey]
	isPending := pendingReqs[connKey]
	mu.Unlock()

	// 如果是响应
	if isResponse {
		if !exists && !isPending {
			return
		}
		
		fmt.Printf("\n[%d] [RESPONSE] %s -> %s\n", reqNum, src, dst)
		printPayload(payload, true)
		fmt.Println(strings.Repeat("-", 80))
		
		// 响应完成，增加计数并清理
		mu.Lock()
		if isPending {
			capturedCount++
			delete(pendingReqs, connKey)
		}
		delete(connMap, connKey)
		mu.Unlock()
		return
	}

	// 请求包：应用过滤条件
	matchSrc := cfg.SrcFilter == "" || strings.Contains(src, cfg.SrcFilter)
	
	matchDst := len(cfg.DstFilters) == 0
	if !matchDst {
		for _, filter := range cfg.DstFilters {
			if strings.Contains(dst, filter) {
				matchDst = true
				break
			}
		}
	}
	
	if !matchSrc || !matchDst {
		return
	}

	if cfg.URIFilter != "" {
		if !strings.Contains(payload, cfg.URIFilter) {
			return
		}
	}

	// 记录新请求（暂不计数）
	mu.Lock()
	reqNum = capturedCount + len(pendingReqs) + 1
	connMap[connKey] = reqNum
	pendingReqs[connKey] = true
	mu.Unlock()

	fmt.Printf("\n[%d] [REQUEST] %s -> %s\n", reqNum, src, dst)
	printPayload(payload, false)
}

func printPayload(payload string, isResponse bool) {
	lines := strings.Split(payload, "\r\n")
	
	if isResponse {
		// 响应：打印状态行和头部
		bodyLines := []string{}
		
		for i, line := range lines {
			if line == "" {
				if i < len(lines)-1 {
					bodyLines = lines[i+1:]
				}
				break
			}
			fmt.Println(line)
		}
		
		// 打印响应体
		if len(bodyLines) > 0 {
			fmt.Println()
			body := strings.Join(bodyLines, "\n")
			if len(body) > 10000 {
				fmt.Println(body[:10000] + "\n... (truncated)")
			} else {
				fmt.Println(body)
			}
		}
	} else {
		// 请求：只打印前20行
		maxLines := 20
		if len(lines) > maxLines {
			lines = lines[:maxLines]
		}
		for _, line := range lines {
			if line == "" {
				break
			}
			fmt.Println(line)
		}
	}
}

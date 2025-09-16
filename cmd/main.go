package main

import (
	"context"
	"encoding/binary"
	"flag"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	defaultPrefixes = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
)

var logger = logrus.New()

// defaultNmapTop1000PortsCSV contains the Nmap top 1000 TCP ports (per nmap-services frequency)
const defaultNmapTop1000PortsCSV = "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,129,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,701,702,706,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4664,4672,4711,4712,4725,4732,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6060,6061,6062,6063,6064,6065,6066,6069,6070,6071,6072,6073,6080,6081,6082,6090,6100,6101,6106,6112,6123,6129,6156,6346,6347,6350,6379,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,6999,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000"

func main() {

	// Flags
	logLevelFlag := flag.String("log", "info", "log level (debug, info, warn, error, fatal, panic)")
	workers := flag.Int("workers", 100, "number of concurrent workers")
	sample16Init := flag.Int("sample16-init", 10, "initial number of /24s to sample per /16 in phase1")
	sample16Max := flag.Int("sample16-max", 20, "maximum number of /24s to sample per /16 in phase1 (adaptive)")
	sample24 := flag.Int("sample24", 10, "number of hosts to sample per /24 in phase2")
	maxConcurrency := flag.Int("max-concurrency", 16, "max concurrent dials per check (per /24) — tunable")
	portList := flag.String("ports", "", "comma-separated ports to probe (default: Nmap top 100 TCP ports)")
	nmapTop := flag.Int("top-ports", 0, "use built-in Nmap Top N TCP ports (100). If >0, overrides -ports")
	timeout := flag.Duration("timeout", 1*time.Second, "dial timeout per probe")
	defaultPrefixesCSV := strings.Join(defaultPrefixes, ",")
	// default for -prefixes is empty to prefer auto-detected local networks; if empty after flag parsing, we'll fall back to RFC1918
	prefixes := flag.String("prefixes", "", "comma-separated prefixes to scan (default: auto-detected local; else RFC1918)")
	localOnly := flag.Bool("local-only", false, "only scan auto-detected local IPv4 networks; do not fall back to RFC1918 when none detected")
	dialRate := flag.Int("dial-rate", 200, "global limit for TCP dials per second (default: 200)")
	flag.Parse()

	// Determine prefixes to scan based on flags
	if strings.TrimSpace(*prefixes) != "" {
		if *localOnly {
			logger.Warn("-local-only specified but -prefixes also provided; ignoring -local-only and using -prefixes")
		}
	} else {
		locals := localIPv4CIDRs()
		if len(locals) > 0 {
			*prefixes = strings.Join(locals, ",")
			msg := "auto-detected local prefixes; override with -prefixes to change"
			if *localOnly {
				msg = msg + " (local-only)"
			}
			logger.WithField("prefixes", *prefixes).Info(msg)
		} else {
			if *localOnly {
				logger.Fatal("no local IPv4 prefixes detected; -local-only prevents fallback. Specify -prefixes or connect to a network.")
			}
			// fall back to RFC1918 if nothing is detected locally and not local-only
			*prefixes = defaultPrefixesCSV
			logger.WithField("prefixes", *prefixes).Info("no local IPv4 prefixes detected; falling back to RFC1918 defaults (override with -prefixes)")
		}
	}

	logLevel, err := logrus.ParseLevel(*logLevelFlag)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(logLevel)

	// Global dial rate limiter (req per second)
	tokens := make(chan struct{}, *dialRate)
	// prefill bucket
	for i := 0; i < *dialRate; i++ {
		tokens <- struct{}{}
	}
	go func(rate int) {
		if rate <= 0 {
			return
		}
		t := time.NewTicker(time.Second / time.Duration(rate))
		defer t.Stop()
		for range t.C {
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}(*dialRate)

	// Determine effective ports based on -nmap-top override
	if *portList == "" && *nmapTop == 0 {
		*nmapTop = 100
	}

	if *portList != "" && *nmapTop != 0 {
		logger.Warnf("ignoring -nmap-top value; using -ports %q", *portList)
	}

	if *nmapTop != 0 {
		switch *nmapTop {
		case 100:
			*portList = topNPortsCSVFromCSV(defaultNmapTop1000PortsCSV, 100)
		default:
			logger.Fatal("invalid -nmap-top value; allowed: 100, or 0 to disable")
		}
	}

	var ports []int
	if *portList != "" {
		ports = parsePorts(*portList)
		if len(ports) == 0 {
			logger.Fatal("no ports provided")
		}
	}

	logger.WithField("ports", len(ports)).Info("ports to probe")

	// Build list of /16 networks from prefixes for phase 1
	var sixteenList []uint32
	for _, p := range strings.Split(*prefixes, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ips := expandTo16s(p)
		if len(ips) == 0 {
			logger.Warnf("prefix %q produced no /16s (invalid or too small)", p)
		}
		sixteenList = append(sixteenList, ips...)
	}
	if len(sixteenList) == 0 {
		logger.Fatal("no /16s to scan")
	}

	// Shuffle to add randomness and avoid pathological ordering
	shuffleUint32Slice(sixteenList)

	logger.Debugf("phase1: scanning %d /16s (adaptive sample %d->%d /24s each) with %d workers", len(sixteenList), *sample16Init, *sample16Max, *workers)

	ctx := context.Background()

	// Phase 1: detect active /16s
	in16 := make(chan uint32, len(sixteenList))
	active16ch := make(chan uint32, len(sixteenList))

	var wg16 sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg16.Add(1)
		go func() {
			defer wg16.Done()
			for n := range in16 {
				if check16(ctx, n, *sample16Init, *sample16Max, ports, *timeout, *maxConcurrency) {
					active16ch <- n
				}
			}
		}()
	}

	// feed /16s
	go func() {
		for _, n := range sixteenList {
			in16 <- n
		}
		close(in16)
	}()

	// close active16ch when done
	go func() {
		wg16.Wait()
		close(active16ch)
	}()

	var active16s []uint32
	for n := range active16ch {
		active16s = append(active16s, n)
	}

	if len(active16s) == 0 {
		logger.Info("No active /16s found. Nothing to do.")
		logger.Info("Hint: Default prefixes are private (10/8, 172.16/12, 192.168/16) and are not publicly routable.")
		logger.Info("Specify your reachable networks with -prefixes, e.g. your LAN: -prefixes 192.168.1.0/24")
		logger.Info("For public testing, try something like: -prefixes 8.8.8.0/24 (subject to policy/legal constraints)")
		logger.Info("Also consider increasing -timeout and adjusting -ports to services likely to be open.")
		return
	}

	sort.Slice(active16s, func(i, j int) bool { return active16s[i] < active16s[j] })
	logger.Debugf("phase1 done: found %d active /16s. diving into /24s...", len(active16s))

	// Phase 2: for each active /16, expand to /24s and probe /24s concurrently
	var all24s []uint32
	for _, s16 := range active16s {
		all24s = append(all24s, expand16To24s(s16)...) // returns /24 bases in that /16
	}

	// Shuffle /24s before scanning to spread load
	shuffleUint32Slice(all24s)

	logger.Debugf("phase2: scanning %d /24s (sample %d hosts each) with %d workers", len(all24s), *sample24, *workers)

	in24 := make(chan uint32, len(all24s))
	active24ch := make(chan uint32, len(all24s))

	var wg24 sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg24.Add(1)
		go func() {
			defer wg24.Done()
			for n := range in24 {
				if check24(ctx, n, *sample24, ports, *timeout, *maxConcurrency) {
					active24ch <- n
				}
			}
		}()
	}

	// feed /24s
	go func() {
		for _, n := range all24s {
			in24 <- n
		}
		close(in24)
	}()

	// close active24ch when done
	go func() {
		wg24.Wait()
		close(active24ch)
	}()

	var active24s []uint32
	for n := range active24ch {
		active24s = append(active24s, n)
	}

	if len(active24s) == 0 {
		logger.Infof("No active /24s found under active /16s.")
		return
	}

	sort.Slice(active24s, func(i, j int) bool { return active24s[i] < active24s[j] })
	cidrs := aggregate24sToCIDRs(active24s)

	logger.Debugf("Active routable blocks (aggregated):")
	for _, c := range cidrs {
		logger.Info(" ", c)
	}
	logger.Info("")
	logger.Debugf("Total active /24s: %d -> %d aggregated CIDRs", len(active24s), len(cidrs))
}

// parse ports like "80,443,22"
func parsePorts(s string) []int {
	var p []int
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil {
			logger.Warnf("invalid port %q: %v", tok, err)
			continue
		}
		if n <= 0 || n > 65535 {
			logger.Warnf("port out of range: %d (must be 1-65535)", n)
			continue
		}
		p = append(p, n)
	}
	return p
}

// Shuffle helper for uint32 slices
func shuffleUint32Slice(s []uint32) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// expandTo16s: given a CIDR prefix like "10.0.0.0/8", return slice of base IPs (network) for each /16 inside it
func expandTo16s(cidr string) []uint32 {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		logger.Warnf("invalid CIDR prefix %q: %v", cidr, err)
		return nil
	}
	base := ipToUint32(ipnet.IP)
	maskLen, _ := ipnet.Mask.Size()
	step := uint32(1 << 16) // /16 step = 65536
	networkStart := base & maskToUint32(ipnet.Mask)
	size := uint32(1) << (32 - maskLen)
	networkEnd := networkStart + size
	var res []uint32
	for x := networkStart; x < networkEnd; x += step {
		res = append(res, x)
	}
	return res
}

// expand16To24s: given a /16 base (e.g. 10.1.0.0) return all /24 base IPs inside that /16
func expand16To24s(base16 uint32) []uint32 {
	step := uint32(1 << 8) // /24 step = 256
	var res []uint32
	for x := base16; x < base16+uint32(1<<16); x += step {
		res = append(res, x)
	}
	return res
}

// Adaptive check16: sample a small number of /24s first; if negative, progressively sample more up to max
func check16(ctx context.Context, base16 uint32, sampleInit, sampleMax int, ports []int, timeout time.Duration, maxConcurrency int) bool {
	if sampleInit <= 0 {
		sampleInit = 3
	}
	if sampleMax < sampleInit {
		sampleMax = sampleInit
	}
	// pick unique random /24 bases within this /16
	max24s := 256
	seen := make(map[uint32]struct{}, sampleMax)
	pickN := func(n int) []uint32 {
		out := make([]uint32, 0, n)
		for len(out) < n {
			off := uint32(rand.Intn(max24s))
			s24Base := base16 + (off << 8)
			if _, ok := seen[s24Base]; ok {
				continue
			}
			seen[s24Base] = struct{}{}
			out = append(out, s24Base)
		}
		return out
	}

	// try initial picks with a tiny host sample and short timeout
	initial := sampleInit
	picks := pickN(initial)
	for _, s24 := range picks {
		// probe each s24 with a very small sample (1 host) and shorter timeout to detect activity quickly
		if check24(ctx, s24, 1, ports, timeout/2, maxConcurrency) {
			return true
		}
	}

	// if still negative and allowed, progressively try more /24s
	remaining := sampleMax - initial
	if remaining <= 0 {
		return false
	}
	// cap additional aggressive tries
	capMore := remaining
	if capMore > 12 {
		capMore = 12
	}
	more := pickN(capMore)
	for _, s24 := range more {
		if check24(ctx, s24, 2, ports, timeout, maxConcurrency) {
			return true
		}
	}
	return false
}

// Concurrent/adaptive check24
func check24(ctx context.Context, base uint32, sample int, ports []int, timeout time.Duration, maxConcurrency int) bool {
	if sample <= 0 {
		sample = 1
	}
	if sample > 254 {
		sample = 254
	}

	// tune maxConcurrency if absurd or unavailable
	if maxConcurrency <= 0 {
		maxConcurrency = runtime.NumCPU() * 8
	}
	if maxConcurrency > 512 {
		maxConcurrency = 512
	}

	// pick unique random hosts in this /24
	hosts := make([]int, 0, sample)
	seen := map[int]struct{}{}
	for len(hosts) < sample {
		h := rand.Intn(254) + 1 // 1..254
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}

	// concurrency control
	sem := make(chan struct{}, maxConcurrency)
	var success int32
	var wg sync.WaitGroup
	dialer := net.Dialer{Timeout: timeout}

	probe := func(ipStr string, port int) {
		defer wg.Done()

		if atomic.LoadInt32(&success) != 0 {
			return
		}

		// tiny jitter to spread load
		time.Sleep(time.Duration(rand.Intn(40)) * time.Millisecond)

		select {
		case sem <- struct{}{}:
			// acquired
		default:
			// fallback if sem is full - still try but briefly sleep
			time.Sleep(5 * time.Millisecond)
			sem <- struct{}{}
		}

		defer func() { <-sem }()

		if atomic.LoadInt32(&success) != 0 {
			return
		}

		addr := net.JoinHostPort(ipStr, strconv.Itoa(port))

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			// In debug mode, log which port was open
			logger.WithFields(logrus.Fields{"ip": ipStr, "port": port}).Debug("open port")
			atomic.StoreInt32(&success, 1)
		}
	}

	// launch probes
	for _, h := range hosts {
		if atomic.LoadInt32(&success) != 0 {
			break
		}

		ip := base + uint32(h)
		ipStr := uint32ToIP(ip).String()

		for _, p := range ports {
			if atomic.LoadInt32(&success) != 0 {
				break
			}

			wg.Add(1)

			go probe(ipStr, p)
		}
	}

	// wait for initial probes to finish or succeed
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		// finished initial wave
	case <-ctx.Done():
		return false
	}

	if atomic.LoadInt32(&success) != 0 {
		return true
	}

	// progressive probing if initial sample failed (try to reach 'sample' total)
	if len(hosts) < sample {
		remaining := sample - len(hosts)

		moreHosts := make([]int, 0, remaining)

		for len(moreHosts) < remaining {
			h := rand.Intn(254) + 1
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			moreHosts = append(moreHosts, h)
		}

		for _, h := range moreHosts {
			if atomic.LoadInt32(&success) != 0 {
				break
			}

			ip := base + uint32(h)
			ipStr := uint32ToIP(ip).String()

			for _, p := range ports {
				if atomic.LoadInt32(&success) != 0 {
					break
				}

				wg.Add(1)

				go probe(ipStr, p)
			}
		}

		wg.Wait()
	}

	return atomic.LoadInt32(&success) != 0
}

// utility functions (ip <-> uint32, mask convert, aggregation) - reused from previous version
func maskToUint32(m net.IPMask) uint32 {
	return binary.BigEndian.Uint32(net.IP(m).To4())
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(u uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return net.IP(b)
}

// aggregate24sToCIDRs: takes sorted list of /24 base uint32s and returns minimal CIDR strings covering them.
func aggregate24sToCIDRs(bases []uint32) []string {
	if len(bases) == 0 {
		return nil
	}
	type r struct{ start, end uint32 }
	var ranges []r
	start := bases[0]
	prev := bases[0]
	step := uint32(256)
	for i := 1; i < len(bases); i++ {
		if bases[i] == prev+step {
			prev = bases[i]
			continue
		}
		ranges = append(ranges, r{start: start, end: prev + 255})
		start = bases[i]
		prev = bases[i]
	}
	ranges = append(ranges, r{start: start, end: prev + 255})

	var cidrs []string
	for _, rg := range ranges {
		cidrs = append(cidrs, ipRangeToCIDRs(rg.start, rg.end)...)
	}
	return cidrs
}

// ipRangeToCIDRs returns minimal CIDR list covering inclusive IP range [startBase, endHost].
func ipRangeToCIDRs(startBase, endHost uint32) []string {
	var out []string
	start := startBase
	end := endHost
	for start <= end {
		maxSize := uint32(32 - trailingZeroBits(start))
		maxDiff := uint32(32 - log2(end-start+1))
		size := maxSize
		if maxDiff > size {
			size = maxDiff
		}
		prefixLen := int(size)
		ip := uint32ToIP(start)
		out = append(out, ip.String()+"/"+strconv.Itoa(prefixLen))
		blockSize := uint32(1) << (32 - prefixLen)
		start += blockSize
		if blockSize == 0 {
			break
		}
	}
	return out
}

func trailingZeroBits(x uint32) int {
	if x == 0 {
		return 32
	}
	n := 0
	for (x & 1) == 0 {
		n++
		x >>= 1
	}
	return n
}

func log2(x uint32) int {
	if x == 0 {
		return 0
	}
	n := 31
	for (x>>n)&1 == 0 {
		n--
	}
	return n
}

// topNPortsCSVFromCSV returns a CSV string with the first N tokens from the provided CSV list.
func topNPortsCSVFromCSV(csv string, n int) string {
	parts := strings.Split(csv, ",")
	if n < 0 {
		n = 0
	}
	if n > len(parts) {
		n = len(parts)
	}
	return strings.Join(parts[:n], ",")
}

// localIPv4CIDRs returns a deduplicated list of IPv4 CIDRs from active non-loopback, non-link-local interfaces.
func localIPv4CIDRs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Warnf("cannot list interfaces: %v", err)
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, iface := range ifs {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			// skip 169.254.0.0/16 and 127.0.0.0/8 just in case
			if ip4[0] == 169 && ip4[1] == 254 {
				continue
			}
			if ip4[0] == 127 {
				continue
			}
			// ensure we have a sensible prefix length
			if ones, bits := ipnet.Mask.Size(); bits == 32 && ones > 0 && ones <= 30 {
				cidr := ip4.String() + "/" + strconv.Itoa(ones)
				if _, ok := seen[cidr]; !ok {
					seen[cidr] = struct{}{}
					out = append(out, cidr)
				}
			}
		}
	}
	// If we gathered host IPs, convert them to their network CIDRs for consistency
	for i, cidr := range out {
		_, ipn, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		network := ipn.IP.Mask(ipn.Mask)
		ones, _ := ipn.Mask.Size()
		out[i] = network.String() + "/" + strconv.Itoa(ones)
	}
	// dedupe again after normalization
	ded := make(map[string]struct{})
	var res []string
	for _, c := range out {
		if _, ok := ded[c]; ok {
			continue
		}
		ded[c] = struct{}{}
		res = append(res, c)
	}
	return res
}

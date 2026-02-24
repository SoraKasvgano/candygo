package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

type arguments struct {
	mode        string
	websocket   string
	password    string
	ntp         string
	noTimestamp bool
	debug       bool

	dhcp  string
	sdwan string

	name      string
	tun       string
	stun      string
	localhost string
	port      int
	discovery int
	routeCost int
	mtu       int
}

func (a *arguments) json() jsonObject {
	config := jsonObject{}
	config["mode"] = a.mode
	config["websocket"] = a.websocket
	config["password"] = a.password

	if a.mode == "client" {
		config["name"] = a.name
		config["tun"] = a.tun
		config["stun"] = a.stun
		config["localhost"] = a.localhost
		config["discovery"] = a.discovery
		config["route"] = a.routeCost
		config["mtu"] = a.mtu
		config["port"] = a.port
		config["vmac"] = virtualMac(a.name)
		config["expt"] = loadTunAddress(a.name)
	}

	if a.mode == "server" {
		config["dhcp"] = a.dhcp
		config["sdwan"] = a.sdwan
	}
	return config
}

func (a *arguments) parse(args []string) int {
	fs := pflag.NewFlagSet("candy", pflag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	cfgFile := fs.StringP("config", "c", "", "config file path")
	mode := fs.StringP("mode", "m", "", "working mode")
	websocket := fs.StringP("websocket", "w", "", "websocket address")
	password := fs.StringP("password", "p", "", "authorization password")
	ntp := fs.String("ntp", "", "ntp server address (compatibility field)")
	dhcp := fs.StringP("dhcp", "d", "", "dhcp address range")
	sdwan := fs.String("sdwan", "", "software-defined wide area network")
	name := fs.StringP("name", "n", "", "network interface name")
	tun := fs.StringP("tun", "t", "", "static address")
	stun := fs.StringP("stun", "s", "", "stun address")
	port := fs.Int("port", 0, "p2p listen port")
	mtu := fs.Int("mtu", 1400, "maximum transmission unit")
	route := fs.IntP("route", "r", 0, "routing cost")
	discovery := fs.Int("discovery", 0, "discovery interval")
	localhost := fs.String("localhost", "", "local ip")
	noTimestamp := fs.Bool("no-timestamp", false, "disable timestamps")
	debug := fs.Bool("debug", false, "enable debug logs")
	help := fs.BoolP("help", "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		fmt.Print(fs.FlagUsages())
		return -1
	}
	if *help {
		fmt.Printf("candy %s\n", version())
		fmt.Print(fs.FlagUsages())
		return -1
	}

	if *cfgFile != "" {
		a.parseFile(*cfgFile)
	} else if autoCfg := findDefaultConfig(); autoCfg != "" {
		infof("use default config file: %s", autoCfg)
		a.parseFile(autoCfg)
	}

	if fs.Changed("mode") {
		a.mode = *mode
	}
	if fs.Changed("websocket") {
		a.websocket = *websocket
	}
	if fs.Changed("password") {
		a.password = *password
	}
	if fs.Changed("ntp") {
		a.ntp = *ntp
	}
	if fs.Changed("no-timestamp") {
		a.noTimestamp = *noTimestamp
	}
	if fs.Changed("debug") {
		a.debug = *debug
	}
	if fs.Changed("dhcp") {
		a.dhcp = *dhcp
	}
	if fs.Changed("sdwan") {
		a.sdwan = *sdwan
	}
	if fs.Changed("name") {
		a.name = *name
	}
	if fs.Changed("tun") {
		a.tun = *tun
	}
	if fs.Changed("stun") {
		a.stun = *stun
	}
	if fs.Changed("localhost") {
		a.localhost = *localhost
	}
	if fs.Changed("port") {
		a.port = *port
	}
	if fs.Changed("mtu") {
		a.mtu = *mtu
	}
	if fs.Changed("discovery") {
		a.discovery = *discovery
	}
	if fs.Changed("route") {
		a.routeCost = *route
	}

	needShowUsage := a.mode != "client" && a.mode != "server"
	if strings.TrimSpace(a.websocket) == "" {
		needShowUsage = true
	}
	if needShowUsage {
		fmt.Print(fs.FlagUsages())
		return -1
	}

	setNoTimestamp(a.noTimestamp)
	setDebug(a.debug)
	return 0
}

func (a *arguments) parseFile(cfgFile string) {
	configs, err := a.fileToKvMap(cfgFile)
	if err != nil {
		errorf("parse config file failed: %v", err)
		os.Exit(1)
	}

	trim := func(str string) string {
		str = strings.TrimSpace(str)
		if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
			return str[1 : len(str)-1]
		}
		return str
	}

	for key, value := range configs {
		value = trim(value)
		switch key {
		case "mode":
			a.mode = value
		case "websocket":
			a.websocket = value
		case "password":
			a.password = value
		case "ntp":
			a.ntp = value
		case "debug":
			if b, err := strconv.ParseBool(strings.ToLower(value)); err == nil {
				a.debug = b
			}
		case "dhcp":
			a.dhcp = value
		case "sdwan":
			a.sdwan = value
		case "tun":
			a.tun = value
		case "stun":
			a.stun = value
		case "name":
			a.name = value
		case "discovery":
			a.discovery, _ = strconv.Atoi(value)
		case "route":
			a.routeCost, _ = strconv.Atoi(value)
		case "port":
			a.port, _ = strconv.Atoi(value)
		case "mtu":
			a.mtu, _ = strconv.Atoi(value)
		case "localhost":
			a.localhost = value
		default:
			warnf("unknown config: %s=%s", key, value)
		}
	}
}

func (a *arguments) fileToKvMap(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	config := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, " \t;")
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		config[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

func saveTunAddress(name string, cidr string) int {
	cache := storageDirectory("address")
	if name == "" {
		name = "__noname__"
	}
	path := filepath.Join(cache, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		criticalf("save latest address failed: %v", err)
		return -1
	}
	if err := os.WriteFile(path, []byte(cidr), 0o644); err != nil {
		criticalf("save latest address failed: %v", err)
		return -1
	}
	return 0
}

func loadTunAddress(name string) string {
	if name == "" {
		name = "__noname__"
	}
	path := filepath.Join(storageDirectory("address"), name)
	data, err := os.ReadFile(path)
	if err != nil {
		return "0.0.0.0/0"
	}
	return strings.TrimSpace(string(data))
}

func virtualMacHelper(name string) string {
	if name == "" {
		name = "__noname__"
	}
	path := filepath.Join(storageDirectory("vmac"), name)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(data))
	if len(text) >= VMAC_SIZE {
		return text[:VMAC_SIZE]
	}
	return ""
}

func initVirtualMac() string {
	path := filepath.Join(storageDirectory("vmac"), "__noname__")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		criticalf("init vmac failed: %v", err)
		return ""
	}
	vmac := create_vmac()
	if err := os.WriteFile(path, []byte(vmac), 0o644); err != nil {
		criticalf("init vmac failed: %v", err)
		return ""
	}
	return vmac
}

func virtualMac(name string) string {
	if v := virtualMacHelper(name); v != "" {
		return v
	}
	if v := virtualMacHelper(""); v != "" {
		return v
	}
	return initVirtualMac()
}

func storageDirectory(subdir string) string {
	var base string
	if isWindows() {
		base = "C:/ProgramData/Candy"
	} else {
		base = "/var/lib/candy"
	}
	if subdir == "" {
		return base
	}
	return filepath.Join(base, subdir)
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func findDefaultConfig() string {
	candidates := make([]string, 0, 2)
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "candy.cfg"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "candy.cfg"))
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func requireBind(value string) (string, int, error) {
	idx := strings.LastIndex(value, ":")
	if idx <= 0 || idx == len(value)-1 {
		return "", 0, errors.New("invalid bind format, expected address:port")
	}
	host := value[:idx]
	port, err := strconv.Atoi(value[idx+1:])
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

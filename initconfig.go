package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func initConfigFile(cfgFile string) error {
	target := strings.TrimSpace(cfgFile)
	if target == "" {
		target = "candy.cfg"
	}
	if err := writeTemplateConfig(target); err != nil {
		return err
	}
	infof("initialized config file: %s", target)
	return nil
}

func writeTemplateConfig(path string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file already exists: %s", path)
	}

	const template = `############################## Client and Server ##############################
# [Required] Working mode, "client" or "server"
mode = "client"

# [Required] The address that the server listens on.
# Server supports ws directly, and can expose wss through a reverse proxy.
# Client supports ws and wss.
websocket = "ws://127.0.0.1:26816"

# [Optional] Password used to verify identity
#password = "this is the password"

# [Optional] Show debug log
#debug = false

################################# Server Only #################################
# [Optional] The range of addresses automatically assigned by the server
#dhcp = "192.168.202.0/24"

# [Optional] software-defined wide area network
#sdwan = "192.168.202.1/32,172.17.0.0/16,192.168.202.2"

################################# Client Only #################################
# [Optional] Network interface name
#name = ""

# [Optional] Static address
#tun = "192.168.202.1/24"

# [Optional] STUN server address
stun = "stun://stun.canets.org"

# [Optional] Active discovery interval
discovery = 300

# [Optional] The cost of routing through this machine
route = 5

# [Optional] Local UDP port used for P2P
#port = 0

# [Optional] Local IPv4 address used for peering connections
#localhost = "127.0.0.1"

# [Optional] Maximum Transmission Unit
#mtu = 1400
`
	return os.WriteFile(path, []byte(template), 0o644)
}

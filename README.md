# CandyGo

CandyGo is a pure Go (no cgo) rewrite of the original `candy` project, targeting 1:1 behavior compatibility.

 [candy is an amazing net tool made by lanthora](https://github.com/lanthora/candy)
 
 [WIKI](https://docs.canets.org/)

The project provides:

- client mode: join virtual network (WebSocket control plane + UDP P2P data plane)
- server mode: WebSocket relay + dynamic address allocation + SD-WAN route publish
- service mode: HTTP API (`/api/run`, `/api/status`, `/api/shutdown`)
- the candy.cfg is fully compatible with original candy

## Goals

- Keep protocol and runtime behavior aligned with the original C++ implementation
- Keep naming and function semantics as close as possible
- Prioritize compatibility and stability before adding features

## Requirements

- Go 1.25+
- Windows client mode: `wintun.dll` is required (place near executable or in `System32`)
- Linux/macOS: TUN and route operations usually require root/admin privileges

## Build

```bash
go build ./...
go test ./...
```

## Run

### CLI

```bash
go run . --help
go run . -m client -w ws://127.0.0.1:26816 -t 192.168.202.2/24
go run . -m server -w ws://0.0.0.0:26816 -d 192.168.202.0/24
```

### Service

```bash
go run . service --help
go run . service --bind 0.0.0.0:26817
```

### Windows helper

`run.bat` is provided for Windows startup convenience (including elevation flow).

## Config compatibility

- Supports loading config via `-c /path/to/candy.cfg`
- If `-c` is not provided, it auto-detects:
  - `./candy.cfg`
  - `candy.cfg` in executable directory
- Maintains compatibility with original common keys (`mode`, `websocket`, `password`, `tun`, `stun`, `route`, `dhcp`, `sdwan`, etc.)

## Cross-compile output

Use build scripts to output binaries directly under `dist/`:

- `build.bat` (Windows)
- `build.sh` (Linux)

Generated file naming pattern:

- `dist/candygo-windows-amd64.exe`
- `dist/candygo-linux-amd64`
- `dist/candygo-linux-armv7`
- `dist/candygo-linux-armv8`
- `dist/candygo-linux-mips`
- `dist/candygo-linux-mipsel`

## Docker

The Docker image uses the prebuilt binary from `dist/` (default: `dist/candygo-linux-amd64`).

- `dockerfile`: runtime image definition
- `docker-compose.yml`: host network + privileged container (`candygo`)
- `update-docker.sh`: remove old container/image, rebuild with native `docker build`, recreate container with preserved parameters

Default persistent mounts in compose:

- `/var/lib/candy:/var/lib/candy` (rw)
- `/path/to/candy.cfg:/etc/candy.cfg:ro`

## Project map

Key files:

- entry and mode dispatch: `main.go`
- facade/API: `candy_api.go`
- client/server core: `client_core.go`, `server_core.go`
- websocket protocol: `websocket_messages.go`, `websocket_client.go`, `websocket_server.go`
- p2p/routing: `peer_messages.go`, `peer.go`, `peer_manager.go`
- tun and routes: `tun.go`, `tun_impl.go`, `tun_windows_api.go`
- config and persistence: `config.go`
- service HTTP API: `service.go`

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See `LICENSE` for full text.


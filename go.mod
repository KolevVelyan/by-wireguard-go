module bringyour.com/wireguard

go 1.22.0

toolchain go1.22.5

replace bringyour.com/connect v0.0.0 => ../connect/connect

replace bringyour.com/protocol v0.0.0 => ../connect/protocol/build/bringyour.com/protocol

require (
	bringyour.com/connect v0.0.0
	bringyour.com/protocol v0.0.0
	github.com/google/gopacket v1.1.19
	golang.org/x/crypto v0.13.0
	golang.org/x/net v0.15.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/golang/glog v1.2.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/oklog/ulid/v2 v2.1.0 // indirect
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090 // indirect
	golang.org/x/sys v0.12.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

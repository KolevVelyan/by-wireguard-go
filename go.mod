module golang.zx2c4.com/wireguard

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
	golang.org/x/sys v0.12.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/golang/glog v1.2.1 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/oklog/ulid/v2 v2.1.0 // indirect
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

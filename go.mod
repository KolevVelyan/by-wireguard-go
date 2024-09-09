module bringyour.com/wireguard

go 1.22.0

toolchain go1.22.5

replace bringyour.com/connect v0.0.0 => ../connect/connect

replace bringyour.com/protocol v0.0.0 => ../connect/protocol/build/bringyour.com/protocol

require (
	bringyour.com/connect v0.0.0
	bringyour.com/protocol v0.0.0
	github.com/google/gopacket v1.1.19
	golang.org/x/crypto v0.23.0
	golang.org/x/net v0.25.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require (
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.0 // indirect
	github.com/golang/glog v1.2.1 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/oklog/ulid/v2 v2.1.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/quic-go/quic-go v0.46.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	golang.org/x/tools v0.21.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	src.agwa.name/tlshacks v0.0.0-20231008131857-90d701ba3225 // indirect
)

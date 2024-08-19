/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/rwcancel"

	"bringyour.com/connect"
	"bringyour.com/protocol"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type NATKey struct {
	IP   string
	Port int
}

type NATValue struct {
	IP net.IP
}

type NativeTun struct {
	tunFile                 *os.File
	index                   int32      // if index
	errors                  chan error // async error handling
	events                  chan Event // device related events
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
	batchSize               int

	closeOnce sync.Once

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error

	writeOpMu sync.Mutex // writeOpMu guards toWrite
	toWrite   []int

	natTableMu sync.Mutex
	natTable   map[NATKey]NATValue

	nat       *connect.LocalUserNat
	natCancel context.CancelFunc

	rcvChan chan []byte
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) routineHackListener() {
	defer tun.hackListenerClosed.Unlock()
	/* This is needed for the detection to work across network namespaces
	 * If you are reading this and know a better method, please get in touch.
	 */
	last := 0
	const (
		up   = 1
		down = 2
	)
	for {
		sysconn, err := tun.tunFile.SyscallConn()
		if err != nil {
			return
		}
		err2 := sysconn.Control(func(fd uintptr) {
			_, err = unix.Write(int(fd), nil)
		})
		if err2 != nil {
			return
		}
		switch err {
		case unix.EINVAL:
			if last != up {
				// If the tunnel is up, it reports that write() is
				// allowed but we provided invalid data.
				tun.events <- EventUp
				last = up
			}
		case unix.EIO:
			if last != down {
				// If the tunnel is down, it reports that no I/O
				// is possible, without checking our provided data.
				tun.events <- EventDown
				last = down
			}
		default:
			return
		}
		select {
		case <-time.After(time.Second):
			// nothing
		case <-tun.statusListenersShutdown:
			return
		}
	}
}

func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

func (tun *NativeTun) routineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()

	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf("failed to receive netlink message: %w", err)
			return
		}

		select {
		case <-tun.statusListenersShutdown:
			return
		default:
		}

		wasEverUp := false
		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if int(hdr.Len) > len(remain) {
				break
			}

			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = []byte{}

			case unix.RTM_NEWLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				if info.Index != tun.index {
					// not our interface
					continue
				}

				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- EventUp
					wasEverUp = true
				}

				if info.Flags&unix.IFF_RUNNING == 0 {
					// Don't emit EventDown before we've ever emitted EventUp.
					// This avoids a startup race with HackListener, which
					// might detect Up before we have finished reporting Down.
					if wasEverUp {
						tun.events <- EventDown
					}
				}

				tun.events <- EventMTUUpdate

			default:
				remain = remain[hdr.Len:]
			}
		}
	}
}

func getIFIndex(name string) (int32, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

func (tun *NativeTun) setMTU(n int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}

	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	name, err := tun.Name()
	if err != nil {
		return 0, err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func (tun *NativeTun) Name() (string, error) {
	tun.nameOnce.Do(tun.initNameCache)
	return tun.nameCache, tun.nameErr
}

func (tun *NativeTun) initNameCache() {
	tun.nameCache, tun.nameErr = tun.nameSlow()
}

func (tun *NativeTun) nameSlow() (string, error) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeOpMu.Lock()
	defer tun.writeOpMu.Unlock()
	var (
		errs  error
		total int
	)
	tun.toWrite = tun.toWrite[:0]
	for i := range bufs {
		tun.toWrite = append(tun.toWrite, i)
	}
	for _, bufsI := range tun.toWrite {
		packetData := bufs[bufsI][offset:] // TODO: might need to keep offset in beginning?
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		// parse the IPv4 layer
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				errs = errors.Join(errs, fmt.Errorf("no transport layer found in packet: %+x", packetData))
				continue
			}

			ipv4 := ipv4Layer.(*layers.IPv4)
			localSrcIP := NATValue{IP: ipv4.SrcIP} // get pre NAT IP

			ipv4.SrcIP = net.IPv4(172, 245, 118, 233)
			ipv4.TTL -= 1

			natKey := NATKey{}
			natKey.IP = ipv4.SrcIP.String()

			// set network layer for transport layer's checksum and get port for NAT
			switch t := transportLayer.(type) {
			case *layers.TCP:
				t.SetNetworkLayerForChecksum(ipv4)
				natKey.Port = int(t.SrcPort)
			case *layers.UDP:
				t.SetNetworkLayerForChecksum(ipv4)
				natKey.Port = int(t.SrcPort)
			default:
				errs = errors.Join(errs, fmt.Errorf("unsupported transport layer type: %T", t))
				continue
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			err := gopacket.SerializeLayers(buffer, options, ipv4, transportLayer.(gopacket.SerializableLayer), gopacket.Payload(transportLayer.LayerPayload()))
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to serialize IPv4 packet: %w", err))
				continue
			}

			modifiedPacket := buffer.Bytes()
			ok := tun.nat.SendPacket(connect.Path{}, protocol.ProvideMode_Network, modifiedPacket, 1*time.Second)
			if !ok {
				errs = errors.Join(errs, errors.New("failed to send packet"))
			} else {
				total += 1

				// add nat entry
				tun.natTableMu.Lock()
				tun.natTable[natKey] = localSrcIP
				tun.natTableMu.Unlock()
			}
		} else {
			errs = errors.Join(errs, fmt.Errorf("failed to parse packet"))
		}
	}
	return total, errs
}

func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	case packetData := <-tun.rcvChan:
		readInto := bufs[0][offset:]
		n := copy(readInto, packetData) // copy packet data into the buffer

		if n > len(readInto) {
			return 0, fmt.Errorf("packet too large for buffer")
		}

		sizes[0] = n
		return 1, nil
	}
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		if tun.statusListenersShutdown != nil {
			close(tun.statusListenersShutdown)
			if tun.netlinkCancel != nil {
				err1 = tun.netlinkCancel.Cancel()
			}
		} else if tun.events != nil {
			close(tun.events)
		}
		err2 = tun.tunFile.Close()
	})
	if tun.nat != nil {
		tun.natCancel()
		tun.nat = nil
		tun.natCancel = nil
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *NativeTun) BatchSize() int {
	return tun.batchSize
}

func (tun *NativeTun) initFromFlags(name string) error {
	sc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return err
	}
	if e := sc.Control(func(fd uintptr) {
		var (
			ifr *unix.Ifreq
		)
		ifr, err = unix.NewIfreq(name)
		if err != nil {
			return
		}
		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
		if err != nil {
			return
		}
		tun.batchSize = 1
		// }
	}); e != nil {
		return e
	}
	return err
}

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(name string, mtu int) (Device, error) {
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// where a null write will return EINVAL indicating the TUN is up.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI) // | unix.IFF_VNET_HDR)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	fd := os.NewFile(uintptr(nfd), cloneDevicePath)
	return CreateTUNFromFile(fd, mtu)
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile:                 file,
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
		toWrite:                 make([]int, 0, conn.IdealBatchSize),
	}

	name, err := tun.Name()
	if err != nil {
		return nil, err
	}

	err = tun.initFromFlags(name)
	if err != nil {
		return nil, err
	}

	// start event listener
	tun.index, err = getIFIndex(name)
	if err != nil {
		return nil, err
	}

	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		return nil, err
	}
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	tun.hackListenerClosed.Lock()
	go tun.routineNetlinkListener()
	go tun.routineHackListener() // cross namespace

	err = tun.setMTU(mtu)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	// Create NAT table
	tun.natTable = make(map[NATKey]NATValue)
	tun.rcvChan = make(chan []byte)

	cancelCtx, cancel := context.WithCancel(context.Background())
	clientId := "test-client-id"
	tun.nat = connect.NewLocalUserNatWithDefaults(
		cancelCtx,
		clientId,
	)
	removeCallback := tun.nat.AddReceivePacketCallback(tun.natReceive)
	tun.natCancel = func() {
		removeCallback()
		cancel()
	}

	return tun, nil
}

func (tun *NativeTun) natReceive(source connect.Path, ipProtocol connect.IpProtocol, packet []byte) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)

	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		transportLayer := pkt.TransportLayer()
		if transportLayer == nil {
			fmt.Printf("No transport layer found in packet: %+x", packet)
			return
		}

		ipv4 := ipv4Layer.(*layers.IPv4)

		var dstPort int
		switch t := transportLayer.(type) {
		case *layers.TCP:
			dstPort = int(t.DstPort)
		case *layers.UDP:
			dstPort = int(t.DstPort)
		default:
			fmt.Printf("unsupported transport layer type: %T", t)
			return
		}

		natKey := NATKey{
			IP:   ipv4.DstIP.String(),
			Port: dstPort,
		}

		localDstIP, found := tun.natTable[natKey]
		if !found {
			fmt.Printf("no NAT entry found for %s:%d\n", ipv4.DstIP, dstPort)
			return
		}
		ipv4.DstIP = localDstIP.IP

		// set network layer for transport layer's checksum computation
		switch t := transportLayer.(type) {
		case *layers.TCP:
			t.SetNetworkLayerForChecksum(ipv4)
		case *layers.UDP:
			t.SetNetworkLayerForChecksum(ipv4)
		default:
			fmt.Printf("unsupported transport layer type: %T\n", t)
			return
		}

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err := gopacket.SerializeLayers(buffer, options, ipv4, transportLayer.(gopacket.SerializableLayer), gopacket.Payload(transportLayer.LayerPayload()))
		if err != nil {
			fmt.Printf("failed to serialize modified packet: %v\n", err)
			return
		}

		modifiedPacket := buffer.Bytes()
		tun.rcvChan <- modifiedPacket
	} else {
		fmt.Println("Failed to parse IPv4 layer from the packet")
	}
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file
// descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "/dev/tun")
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 5),
		errors:  make(chan error, 5),
		toWrite: make([]int, 0, conn.IdealBatchSize),
	}
	name, err := tun.Name()
	if err != nil {
		return nil, "", err
	}
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, "", err
	}
	return tun, name, err
}

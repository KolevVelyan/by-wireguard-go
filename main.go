/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/logger"
	"golang.zx2c4.com/wireguard/tun"
)

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
func helperCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// converts key from base64 to hex
func getHexKey(key string) string {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(decodedKey)
}

func main() {
	// set logger to wanted log level (available - LogLevelVerbose, LogLevelError, LogLevelSilent)
	logLevel := logger.LogLevelVerbose // verbose/debug logging
	logger := logger.NewLogger(logLevel, "")

	// tun device
	// TODO: add settings for UserLocalNat when creating UserspaceTUN
	utun, err := tun.CreateUserspaceTUN(logger)
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(1)
	}

	// wireguard device
	device := device.NewDevice(utun, conn.NewDefaultBind(), logger)
	logger.Verbosef("Device started")

	// keys (change these)
	privateKeyServer := "__PLACEHOLDER__"
	publicKeyPeer := "__PLACEHOLDER__"

	// ipcSet (set configuration)
	config := helperCfg(
		"private_key", getHexKey(privateKeyServer),
		"listen_port", "33333",
		"replace_peers", "true",
		"public_key", getHexKey(publicKeyPeer),
		"replace_allowed_ips", "true",
		"allowed_ip", "192.168.90.1/32",
	)
	err = device.IpcSet(config)
	if err != nil {
		logger.Errorf("Failed to Set Config: %v", err)
		os.Exit(1)
		return
	}

	term := make(chan os.Signal, 1) // channel for termination

	device.AddEvent(tun.EventUp) // start up the device

	// wait for program to terminate
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up
	device.Close()
}

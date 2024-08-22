/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfgA(cfg ...string) string {
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

func main() {
	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	logger := device.NewLogger(logLevel, "")
	logger.Verbosef("Starting wireguard-go version %s", Version)

	utun, err := tun.CreateUserspaceTUN()
	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(1)
	}

	device := device.NewDevice(utun, conn.NewDefaultBind(), logger)
	logger.Verbosef("Device started")

	// TODO: ipcSet(config of device)
	inputString1 := "uMQaBFCMKgvMvc9Xvjh1zxVwn9CnXR2/vi+Pl1MaXFw="
	decodedBytes1, err1 := base64.StdEncoding.DecodeString(inputString1)
	if err1 != nil {
		log.Fatal("Error decoding Base64:", err1)
	}
	hexString1 := hex.EncodeToString(decodedBytes1)

	inputString2 := "y4bB/atXsi/OfSpE/rs6mA/J2pL+HyQXBj/um6OkNgs="
	decodedBytes2, err2 := base64.StdEncoding.DecodeString(inputString2)
	if err2 != nil {
		log.Fatal("Error decoding Base64:", err2)
	}
	hexString2 := hex.EncodeToString(decodedBytes2)

	config := uapiCfgA(
		"private_key", hexString1,
		"listen_port", "33344",
		"replace_peers", "true",
		"public_key", hexString2,
		"replace_allowed_ips", "true",
		"allowed_ip", "192.168.90.1/32",
	)
	fmt.Println(config)
	err = device.IpcSet(config)
	if err != nil {
		logger.Errorf("Failed to Set Config: %v", err)
		os.Exit(1)
		return
	}

	term := make(chan os.Signal, 1)

	device.AddEvent(tun.EventUp)

	// wait for program to terminate
	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up
	device.Close()
	logger.Verbosef("Shutting down")
}

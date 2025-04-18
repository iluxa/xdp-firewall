/*
 * Copyright (C) 2025 Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/iluxa/xdp-firewall/internal/firewall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var iface = flag.String("i", "", "interface to attach")
var mode = flag.String("m", "driver", "XDP mode (driver/generic)")
var grpcPort = flag.Uint64("g", 60051, "grpc port")
var logLevel = flag.String("l", "info", "log level (debug/info/warn/error)")

func main() {
	flag.Parse()

	switch *logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		log.Fatal().Str("logLevel", *logLevel).Msg("Wrong log level, only debug/info/warn/error are supported")
	}

	multi := zerolog.MultiLevelWriter(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	if *iface == "" {
		log.Fatal().Msg("No network interfaces specified. Use the -i flag to specify network interface.")
	}
	var isGeneric bool
	if *mode == "driver" {
		isGeneric = false
	} else if *mode == "generic" {
		isGeneric = true
	} else {
		log.Fatal().Str("mode", *mode).Msg("Wrong mode, only driver or generic are supported")
	}

	if *grpcPort > 65535 {
		log.Fatal().Uint64("port", *grpcPort).Msg("Wrong grpc port, only 0-65535 are supported")
	}
	fw, err := firewall.NewFirewall(uint16(*grpcPort))

	if err != nil {
		log.Error().Err(err).Msg("failed to start firewall")
		if errors.Is(err, syscall.EPERM) {
			log.Error().Msg("program requires root privileges. Use 'sudo' or '--privileged' flag.")
		}
		os.Exit(1)
	}
	log.Info().Msg("Firewall started")

	defer func() {
		if err = fw.Stop(); err != nil {
			log.Error().Err(err).Msg("failed to stop firewall")
			os.Exit(2)
		}
		log.Info().Msg("Firewall stopped")
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	err = fw.AttachInterface(*iface, isGeneric)
	if err != nil {
		log.Error().Err(err).Msgf("failed to attach interface: %v", *iface)
		if errors.Is(err, syscall.ENOTSUP) && !isGeneric {
			log.Error().Msg("probably XDP driver mode is not supported on this kernel version. Use '-m generic' to use XDP generic mode.")
		}
		os.Exit(3)
	}

	<-stop
}

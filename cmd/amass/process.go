// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
)

func engineIsRunning() bool {
	c, err := client.NewClient("http://127.0.0.1:" + enginePort())
	if err != nil {
		return false
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return c.HealthCheck(ctx)
}

func startEngine() error {
	p, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	if p == "" {
		return fmt.Errorf("executable path is empty")
	}

	cmd := initCmd(p)
	if cmd == nil {
		return fmt.Errorf("failed to initialize command for %s", p)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = os.Stdin

	cmd.Dir, err = os.Getwd()
	if err != nil {
		return err
	}

	return cmd.Start()
}

// enginePort returns the port the engine API listens on: AMASS_ENGINE_PORT
// when set, otherwise 4000.
func enginePort() string {
	if p := os.Getenv("AMASS_ENGINE_PORT"); p != "" {
		return p
	}
	return "4000"
}

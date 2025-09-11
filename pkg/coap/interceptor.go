// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

import (
	"context"

	"github.com/plgd-dev/go-coap/v3/message/pool"
)

// Interceptor is an interface for mGate intercept hook.
type Interceptor interface {
	// Intercept is called on every message flowing through the Proxy.
	// Messages can be modified before being sent to the server.
	// If the interceptor returns a non-nil packet, the modified packet is sent.
	// The error indicates unsuccessful interception and mGate is cancelling the packet.
	Intercept(ctx context.Context, msg *pool.Message) (*pool.Message, error)
}

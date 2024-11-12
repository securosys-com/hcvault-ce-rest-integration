// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/eventlogger"
)

var _ eventlogger.Node = (*StdoutSink)(nil)

// StdoutSink is structure that implements the eventlogger.Node interface
// as a Sink node that writes the events to the standard output stream.
type StdoutSink struct {
	requiredFormat string
}

// NewStdoutSinkNode creates a new StdoutSink that will persist the events
// it processes using the specified expected format.
func NewStdoutSinkNode(format string) *StdoutSink {
	return &StdoutSink{
		requiredFormat: format,
	}
}

// Process persists the provided eventlogger.Event to the standard output stream.
func (s *StdoutSink) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(StdoutSink).Process"

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if e == nil {
		return nil, fmt.Errorf("%s: event is nil: %w", op, ErrInvalidParameter)
	}

	formattedBytes, found := e.Format(s.requiredFormat)
	if !found {
		return nil, fmt.Errorf("%s: unable to retrieve event formatted as %q", op, s.requiredFormat)
	}

	_, err := os.Stdout.Write(formattedBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: error writing to stdout: %w", op, err)
	}

	// Return nil, nil to indicate the pipeline is complete.
	return nil, nil
}

// Reopen is a no-op for the StdoutSink type.
func (s *StdoutSink) Reopen() error {
	return nil
}

// Type returns the eventlogger.NodeTypeSink constant.
func (s *StdoutSink) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeSink
}

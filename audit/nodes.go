// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/vault/internal/observability/event"
	"github.com/hashicorp/vault/sdk/logical"
)

// ProcessManual will attempt to create an (audit) event with the specified data
// and manually iterate over the supplied nodes calling Process on each.
// Order of IDs in the NodeID slice determines the order they are processed.
// (Audit) Event will be of RequestType (as opposed to ResponseType).
// The last node must be a sink node (eventlogger.NodeTypeSink).
func ProcessManual(ctx context.Context, data *logical.LogInput, ids []eventlogger.NodeID, nodes map[eventlogger.NodeID]eventlogger.Node) error {
	switch {
	case data == nil:
		return errors.New("data cannot be nil")
	case len(ids) < 2:
		return errors.New("minimum of 2 ids are required")
	case nodes == nil:
		return errors.New("nodes cannot be nil")
	case len(nodes) == 0:
		return errors.New("nodes are required")
	}

	// Create an audit event.
	a, err := NewEvent(RequestType)
	if err != nil {
		return err
	}

	// Insert the data into the audit event.
	a.Data = data

	// Create an eventlogger event with the audit event as the payload.
	e := &eventlogger.Event{
		Type:      eventlogger.EventType(event.AuditType.String()),
		CreatedAt: time.Now(),
		Formatted: make(map[string][]byte),
		Payload:   a,
	}

	var lastSeen eventlogger.NodeType

	// Process nodes in order, updating the event with the result.
	// This means we *should* do:
	// 1. formatter (temporary)
	// 2. sink
	for _, id := range ids {
		node, ok := nodes[id]
		if !ok {
			return fmt.Errorf("node not found: %v", id)
		}

		switch node.Type() {
		case eventlogger.NodeTypeFormatter:
			// Use a temporary formatter node  which doesn't persist its salt anywhere.
			if formatNode, ok := node.(*EntryFormatter); ok && formatNode != nil {
				e, err = newTemporaryEntryFormatter(formatNode).Process(ctx, e)
			}
		default:
			e, err = node.Process(ctx, e)
		}

		if err != nil {
			return err
		}

		// Track the last node we have processed, as we should end with a sink.
		lastSeen = node.Type()
	}

	if lastSeen != eventlogger.NodeTypeSink {
		return errors.New("last node must be a sink")
	}

	return nil
}

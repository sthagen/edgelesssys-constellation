/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package gcp

import (
	"context"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/googleapis/gax-go/v2"
)

type forwardingRuleIterator interface {
	Next() (*computepb.ForwardingRule, error)
}

type instanceIterator interface {
	Next() (*computepb.Instance, error)
}

type zoneIterator interface {
	Next() (*computepb.Zone, error)
}

type globalForwardingRulesClient struct {
	*compute.GlobalForwardingRulesClient
}

func (c *globalForwardingRulesClient) Close() error {
	return c.GlobalForwardingRulesClient.Close()
}

func (c *globalForwardingRulesClient) List(ctx context.Context, req *computepb.ListGlobalForwardingRulesRequest,
	_ ...gax.CallOption,
) forwardingRuleIterator {
	return c.GlobalForwardingRulesClient.List(ctx, req)
}

type regionalForwardingRulesClient struct {
	*compute.ForwardingRulesClient
}

func (c *regionalForwardingRulesClient) Close() error {
	return c.ForwardingRulesClient.Close()
}

func (c *regionalForwardingRulesClient) List(ctx context.Context, req *computepb.ListForwardingRulesRequest,
	_ ...gax.CallOption,
) forwardingRuleIterator {
	return c.ForwardingRulesClient.List(ctx, req)
}

type instanceClient struct {
	*compute.InstancesClient
}

func (c *instanceClient) Close() error {
	return c.InstancesClient.Close()
}

func (c *instanceClient) List(ctx context.Context, req *computepb.ListInstancesRequest,
	_ ...gax.CallOption,
) instanceIterator {
	return c.InstancesClient.List(ctx, req)
}

type zoneClient struct {
	*compute.ZonesClient
}

func (c *zoneClient) Close() error {
	return c.ZonesClient.Close()
}

func (c *zoneClient) List(ctx context.Context, req *computepb.ListZonesRequest, opts ...gax.CallOption) zoneIterator {
	return c.ZonesClient.List(ctx, req, opts...)
}

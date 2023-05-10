/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// GetNodeImage returns the image name of the node.
func (c *Client) GetNodeImage(ctx context.Context, providerID string) (string, error) {
	instanceName := getInstanceNameFromProviderID(providerID)

	params := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			instanceName,
		},
	}

	resp, err := c.ec2Client.DescribeInstances(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to describe instances: %w", err)
	}

	if len(resp.Reservations) == 0 {
		return "", fmt.Errorf("no reservations for instance %q", instanceName)
	}

	if len(resp.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instances for instance %q", instanceName)
	}

	if resp.Reservations[0].Instances[0].ImageId == nil {
		return "", fmt.Errorf("no image for instance %q", instanceName)
	}

	return *resp.Reservations[0].Instances[0].ImageId, nil
}

// GetScalingGroupID returns the scaling group ID of the node.
func (c *Client) GetScalingGroupID(ctx context.Context, providerID string) (string, error) {
	instanceName := getInstanceNameFromProviderID(providerID)
	params := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			instanceName,
		},
	}

	resp, err := c.ec2Client.DescribeInstances(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to describe instances: %w", err)
	}

	if len(resp.Reservations) == 0 {
		return "", fmt.Errorf("no reservations for instance %q", instanceName)
	}

	if len(resp.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instances for instance %q", instanceName)
	}

	if resp.Reservations[0].Instances[0].Tags == nil {
		return "", fmt.Errorf("no tags for instance %q", instanceName)
	}

	for _, tag := range resp.Reservations[0].Instances[0].Tags {
		if *tag.Key == "aws:autoscaling:groupName" {
			return *tag.Value, nil
		}
	}

	return "", fmt.Errorf("node %q does not have valid tags", providerID)
}

// CreateNode creates a node in the specified scaling group.
func (c *Client) CreateNode(ctx context.Context, scalingGroupID string) (nodeName, providerID string, err error) {
	containsInstance := func(instances []types.Instance, instance types.Instance) bool {
		for _, i := range instances {
			if *i.InstanceId == *instance.InstanceId {
				return true
			}
		}
		return false
	}

	// 1. Get current capacity
	groups, err := c.scalingClient.DescribeAutoScalingGroups(
		ctx,
		&autoscaling.DescribeAutoScalingGroupsInput{
			AutoScalingGroupNames: []string{scalingGroupID},
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to describe autoscaling group: %w", err)
	}

	if len(groups.AutoScalingGroups) != 1 {
		return "", "", fmt.Errorf("expected exactly one autoscaling group, got %d", len(groups.AutoScalingGroups))
	}

	currentCapacity := int(*groups.AutoScalingGroups[0].DesiredCapacity)

	// 2. Get current list of instances
	previousInstances := groups.AutoScalingGroups[0].Instances

	// 3. Create new instance by increasing capacity by 1
	_, err = c.scalingClient.SetDesiredCapacity(
		ctx,
		&autoscaling.SetDesiredCapacityInput{
			AutoScalingGroupName: &scalingGroupID,
			DesiredCapacity:      toPtr(int32(currentCapacity + 1)),
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to set desired capacity: %w", err)
	}

	// 4. poll until new instance is created with 30 second timeout
	newInstance := types.Instance{}
	for i := 0; i < 30; i++ {
		groups, err := c.scalingClient.DescribeAutoScalingGroups(
			ctx,
			&autoscaling.DescribeAutoScalingGroupsInput{
				AutoScalingGroupNames: []string{scalingGroupID},
			},
		)
		if err != nil {
			return "", "", fmt.Errorf("failed to describe autoscaling group: %w", err)
		}

		if len(groups.AutoScalingGroups) != 1 {
			return "", "", fmt.Errorf("expected exactly one autoscaling group, got %d", len(groups.AutoScalingGroups))
		}

		for _, instance := range groups.AutoScalingGroups[0].Instances {
			if !containsInstance(previousInstances, instance) {
				newInstance = instance
				break
			}
		}

		// break if new instance is found
		if newInstance.InstanceId != nil {
			break
		}

		// wait 1 second
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("context cancelled")
		case <-time.After(1 * time.Second):
		}
	}

	if newInstance.InstanceId == nil {
		return "", "", fmt.Errorf("timed out waiting for new instance")
	}

	if newInstance.AvailabilityZone == nil {
		return "", "", fmt.Errorf("new instance %s does not have availability zone", *newInstance.InstanceId)
	}

	// 7. Return new instance
	return *newInstance.InstanceId, fmt.Sprintf("aws:///%s/%s", *newInstance.AvailabilityZone, *newInstance.InstanceId), nil
}

// DeleteNode deletes a node from the specified scaling group.
func (c *Client) DeleteNode(ctx context.Context, providerID string) error {
	instanceID := getInstanceNameFromProviderID(providerID)

	_, err := c.scalingClient.TerminateInstanceInAutoScalingGroup(
		ctx,
		&autoscaling.TerminateInstanceInAutoScalingGroupInput{
			InstanceId:                     &instanceID,
			ShouldDecrementDesiredCapacity: toPtr(true),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to terminate instance: %w", err)
	}

	return nil
}

func toPtr[T any](v T) *T {
	return &v
}

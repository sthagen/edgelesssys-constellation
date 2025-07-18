/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package controllers

import (
	"context"
	"sync"
)

type fakeScalingGroupUpdater struct {
	sync.RWMutex
	scalingGroupImage map[string]string
}

func newFakeScalingGroupUpdater() *fakeScalingGroupUpdater {
	return &fakeScalingGroupUpdater{
		scalingGroupImage: make(map[string]string),
	}
}

func (u *fakeScalingGroupUpdater) GetScalingGroupImage(_ context.Context, scalingGroupID string) (string, error) {
	u.RLock()
	defer u.RUnlock()
	return u.scalingGroupImage[scalingGroupID], nil
}

func (u *fakeScalingGroupUpdater) SetScalingGroupImage(_ context.Context, scalingGroupID, imageURI string) error {
	u.Lock()
	defer u.Unlock()
	u.scalingGroupImage[scalingGroupID] = imageURI
	return nil
}

func (u *fakeScalingGroupUpdater) reset() {
	u.Lock()
	defer u.Unlock()
	u.scalingGroupImage = make(map[string]string)
}

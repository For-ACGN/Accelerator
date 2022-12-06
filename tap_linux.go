package accelerator

import (
	"github.com/pkg/errors"
	"github.com/songgao/water"
)

func newTAP(cfg *ClientConfig) (*water.Interface, error) {
	c := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: cfg.TAP.DeviceName,
		},
	}
	tap, err := water.New(c)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open tap device")
	}
	return tap, nil
}

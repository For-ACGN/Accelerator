//go:build !windows && !linux

package accelerator

import (
	"runtime"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

func newTAP(cfg *ClientConfig) (*water.Interface, error) {
	return nil, errors.Errorf("%s is not supported", runtime.GOOS)
}

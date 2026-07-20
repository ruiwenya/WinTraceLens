//go:build !windows

package driveranalysis

func collectDriverServices() ([]serviceEntry, error) {
	return nil, nil
}

func collectDriverEvents(max int) ([]eventEntry, []string) {
	return nil, nil
}

func collectDriverFiles() ([]diskEntry, error) {
	return nil, nil
}

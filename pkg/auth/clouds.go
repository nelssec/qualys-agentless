package auth

var availableCloudProviders []string

func registerCloudProvider(name string) {
	availableCloudProviders = append(availableCloudProviders, name)
}

func AvailableCloudProviders() []string {
	return availableCloudProviders
}

func HasCloudProvider(name string) bool {
	for _, p := range availableCloudProviders {
		if p == name {
			return true
		}
	}
	return false
}

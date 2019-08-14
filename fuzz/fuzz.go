// +build gofuzz

package samlfuzz

import (
	"encoding/base64"
)

var serviceProvider = newServiceProvider()

func Fuzz(input []byte) int {

	base64Input := base64.StdEncoding.EncodeToString(input)

	if _, err := serviceProvider.ValidateEncodedResponse(base64Input); err != nil {
		return 0
	}

	if _, err := serviceProvider.RetrieveAssertionInfo(base64Input); err != nil {
		return 1
	}
	return 1
}

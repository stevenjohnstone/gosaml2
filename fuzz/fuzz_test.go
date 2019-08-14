package samlfuzz

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func TestCorpus(t *testing.T) {
	corpus, err := ioutil.ReadDir("./corpus")
	if err != nil {
		panic(err)
	}

	serviceProvider := newServiceProvider()

	for _, f := range corpus {
		data, err := ioutil.ReadFile("./corpus/" + f.Name())
		if err != nil {
			panic(err)
		}

		base64Input := base64.StdEncoding.EncodeToString(data)

		if _, err := serviceProvider.ValidateEncodedResponse(base64Input); err == nil {
			if _, err := serviceProvider.RetrieveAssertionInfo(base64Input); err != nil {
				t.Log(err)
			}
		}
	}
}

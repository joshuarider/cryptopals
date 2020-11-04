package parse

import "strings"

func Cookie(payload string) map[string]string {
	output := make(map[string]string)

	chunks := strings.Split(payload, "&")

	for _, chunk := range chunks {
		kv := strings.Split(chunk, "=")

		if len(kv) == 1 {
			output[kv[0]] = ""
			continue
		}

		output[kv[0]] = kv[1]
	}

	return output
}

package masking

import (
	"fmt"
	"strings"
)

// Email default masking method
func Email(value string) (ret string, err error) {
	s := strings.Split(value, "@")
	if len(s) == 2 {
		left, err := ReserveMargin(s[0], 1, "*")
		if err != nil {
			return ret, fmt.Errorf("unable to apply left margin: %w", err)
		}

		right, err := ReserveMargin(s[1], 1, "*")
		if err != nil {
			return ret, fmt.Errorf("unable to apply right margin: %w", err)
		}

		ret = left + "@" + right
	}
	return ret, err
}

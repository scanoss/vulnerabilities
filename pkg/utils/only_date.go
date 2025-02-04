package utils

import (
	"fmt"
	"strings"
	"time"
)

type OnlyDate time.Time

const ctLayout = "2006-01-02"

// UnmarshalJSON Parses the json string in the custom format.
func (ct *OnlyDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	nt, err := time.Parse(ctLayout, s)
	if err != nil {
		return err
	}
	*ct = OnlyDate(nt)
	return nil
}

// MarshalJSON writes a quoted string in the custom format.
func (ct OnlyDate) MarshalJSON() ([]byte, error) {
	return []byte(ct.String()), nil
}

// String returns the time in the custom format.
func (ct *OnlyDate) String() string {
	t := time.Time(*ct)
	return fmt.Sprintf("%q", t.Format(ctLayout))
}

func ParseTime(t string) time.Time {
	timeValue, err := time.Parse(time.DateOnly, t)
	if err != nil {
		panic(err)
	}
	return timeValue
}

package utils

import (
	"fmt"
	"testing"
)

func TestOnlyDate(t *testing.T) {
	var onlyDate OnlyDate

	stringDate := "2022-02-28"
	err := onlyDate.UnmarshalJSON([]byte(stringDate))
	if err != nil {
		t.Errorf("Cannot parse date %v - err: %v", stringDate, err)
	}

	fmt.Printf("Parsed date: %v", onlyDate.String())
}

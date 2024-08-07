package api

import (
	"encoding/json"
	"fmt"
	"myserver/model"
	"net/http"
)

func GetCurrentLocation() (float64, float64, error) {
	url := "http://ip-api.com/json/"
	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, fmt.Errorf("Failed to get current Location: %v ", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	var loc model.Location
	err = json.NewDecoder(resp.Body).Decode(&loc)

	if err != nil {
		return 0, 0, fmt.Errorf("Failed to decode response :%v", err)
	}

	return loc.Latitude, loc.Longitude, nil
}

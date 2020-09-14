package networking

import (
	"encoding/json"
	"github.com/google/gopacket/pcap"
	"log"
)

type DeviceInfo struct {
	Name        string
	Description string
}

func GetDevices() ([]byte, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println(err)
	}
	devicesSlice := make([]DeviceInfo, 0)
	for _, device := range devices {
		deviceInfo := DeviceInfo{
			Name:        device.Name,
			Description: device.Description,
		}
		devicesSlice = append(devicesSlice, deviceInfo)
	}
	devicesJson, _ := json.Marshal(devicesSlice)
	return devicesJson, err
}

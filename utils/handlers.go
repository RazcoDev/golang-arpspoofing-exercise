package utils

import (
	"first-app/networking"
	"net/http"
	"time"
	//"time"
)

func SpooferHandler(w http.ResponseWriter, r *http.Request) {
	sniffDevice := "\\Device\\NPF_{33A8362E-167C-4E5D-AD66-519603123CC9}"
	a := 0.1
	snifferDuration := time.Duration(10)
	afConn := networking.NewArpfoxConn("Ethernet", a, "192.168.1.128", "192.168.1.1", snifferDuration)
	go func() {
		networking.Start_spoofing_session(*afConn)
	}()
	dnsQueries, err := networking.GetDNSQueries(sniffDevice, snifferDuration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(dnsQueries)

}

func DevicesHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := networking.GetDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(devices)

}

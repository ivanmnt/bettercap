package network

import (
	"fmt"
	"strings"
	"sync"

	"github.com/bettercap/bettercap/core"
)

type ArpTable map[string]string

var (
	arpLock     // sync.RWMutex is better than &sync.RWMutex{} this way I don't create a new object
	arpTable     = make(ArpTable)
	arpWasParsed bool
)

func ArpUpdate(iface string) (ArpTable, error) {
	arpLock.Lock()
	defer arpLock.Unlock()

	arpWasParsed = true

	output, err := core.Exec(ArpCmd, ArpCmdOpts)
	if err != nil {
		return arpTable, err
	}

	newTable := make(ArpTable)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := ArpTableParser.FindStringSubmatch(line)
		if len(matches) == ArpTableTokens {
			ipIndex := ArpTableTokenIndex[0]
			hwIndex := ArpTableTokenIndex[1]
			ifIndex := ArpTableTokenIndex[2]

			address := matches[ipIndex]
			mac := matches[hwIndex]
			ifname := iface

			if ifIndex != -1 {
				ifname = matches[ifIndex]
			}

			if ifname == iface {
				newTable[address] = mac
			}
		}
	}

	arpTable = newTable

	return arpTable, nil
}

func ArpLookup(iface string, address string, refresh bool) (string, error) {
	if !ArpParsed() || refresh {
		if _, err := ArpUpdate(iface); err != nil {
			return "", err
		}
	}

	arpLock.RLock()
	defer arpLock.RUnlock()

	mac, found := arpTable[address]
	if found {
		return mac, nil
	}

	return "", fmt.Errorf("Could not find MAC for %s", address)
}

func ArpInverseLookup(iface string, mac string, refresh bool) (string, error) {
	if !ArpParsed() || refresh {
		if _, err := ArpUpdate(iface); err != nil {
			return "", err
		}
	}

	arpLock.RLock()
	defer arpLock.RUnlock()

	for ip, hw := range arpTable {
		if hw == mac {
			return ip, nil
		}
	}

	return "", fmt.Errorf("Could not find IP for %s", mac)
}

func ArpParsed() bool {
	arpLock.RLock()
	defer arpLock.RUnlock()

	return arpWasParsed
}

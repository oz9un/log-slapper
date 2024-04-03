package splunk

import (
	"crypto/rand"
	"math/big"
	"net"
)

// randomIPFromRange generates a random IP address within the given CIDR range.
func randomIpFromCIDR(cidr string) (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Determine the IP address range by finding the network start and the broadcast address.
	var max big.Int
	// Count the bits of the network mask
	ones, bits := ipnet.Mask.Size()

	// The total number of IP addresses in the range is 2^(total bits - network bits)
	max.Exp(big.NewInt(2), big.NewInt(int64(bits-ones)), nil)

	// Generate a random big integer within the range
	randomBigInt, err := rand.Int(rand.Reader, &max)
	if err != nil {
		return nil, err
	}

	// Add the random offset to the network start to get the random IP
	randomIPBytes := randomBigInt.Bytes()
	networkStart := big.NewInt(0).SetBytes(ipnet.IP.To16())

	// Ensure the random part fits in the IP bytes slice
	randomIPInt := big.NewInt(0).Add(networkStart, big.NewInt(0).SetBytes(randomIPBytes))
	randomIP := randomIPInt.Bytes()

	// If IPv4, ensure we return an IPv4 address by slicing the last 4 bytes if necessary
	if bits == 32 && len(randomIP) > net.IPv4len {
		randomIP = randomIP[len(randomIP)-net.IPv4len:]
	}

	return net.IP(randomIP), nil
}

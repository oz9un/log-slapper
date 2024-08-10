package splunk

// encodeBase128 encodes an integer to base128 encoding.
func encodeBase128(value int64) []byte {
	var parts []byte
	for value > 0 {
		b := byte(value & 0x7F) // Explicitly cast to byte
		value >>= 7
		if value > 0 {
			b |= 0x80
		}
		parts = append(parts, b)
	}

	return parts
}

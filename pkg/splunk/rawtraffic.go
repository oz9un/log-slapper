package splunk

import (
	"bytes"
	"fmt"
)

// formatAsHexString formats a byte slice as a string of hexadecimal escape sequences.
func formatAsHexString(data []byte) string {
	result := ""
	for _, b := range data {
		result += fmt.Sprintf("\\x%02x", b)
	}
	return result
}

//////////////////////

func createHostnamePart(hostname string) []byte {
	var buffer bytes.Buffer

	// Append 103 null bytes
	buffer.Write(bytes.Repeat([]byte{0x00}, 103))

	// Append the hostname
	buffer.WriteString(hostname)

	// Calculate the remaining length to pad with null bytes and append them
	remainingLength := 256 - len(hostname)
	if remainingLength > 0 {
		buffer.Write(bytes.Repeat([]byte{0x00}, remainingLength))
	}

	return buffer.Bytes()
}

// prepareHelloData prepares the initial data to be sent to the Splunk server.
func PrepareHelloData(hostname string) []byte {
	var buffer bytes.Buffer

	cookMode := []byte("--splunk-cooked-mode-v3--")
	hostnamePart := createHostnamePart(hostname)

	finalPart := []byte("8089\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x01\x00\x00\x00\x13__s2s_capabilities\x00\x00\x00\x00\x14ack=0;compression=0\x00\x00\x00\x00\x00\x00\x00\x00\x05_raw\x00")

	// Append parts to the buffer
	buffer.Write(cookMode)
	buffer.Write(hostnamePart)
	buffer.Write(finalPart)

	finalData := buffer.Bytes()
	return finalData
}

// appendKeyValue appends a key-value pair to the buffer with the format <total-length><key>::<value>.
func appendKeyValue(buffer *bytes.Buffer, key, value string) {
	// Calculate the total length (key length + 2 for "::" + value length) and one extra
	totalLength := len(key) + len("::") + len(value) + 1

	// Append total length as a byte (assuming the total length fits in one byte)
	buffer.WriteByte(byte(totalLength))

	// Append key, "::", and value
	buffer.WriteString(key)
	buffer.WriteString("::")
	buffer.WriteString(value)
}

// prepareEventData prepares the event data with source, host, and sourcetype.
func preparePreEventData(source, host, sourcetype string, epochtime int64) []byte {
	var buffer bytes.Buffer

	// Initial part of the payload
	initialPart := []byte("\xfe\x02")
	buffer.Write(initialPart)

	// Append source, host, and sourcetype key-value pairs
	appendKeyValue(&buffer, "source", source)
	appendKeyValue(&buffer, "host", host)
	appendKeyValue(&buffer, "sourcetype", sourcetype)

	// Example of appending binary data (customizable as needed)
	binaryData := []byte{0x00, 0x00, 0xfc, 0x02, 0xff, 0x05, 0xa4, 0xf6, 0x96, 0xda, 0xf7, 0xc7, 0xf7, 0xb2, 0xb1, 0x01, 0xfd, 0x9e, 0xcd, 0x05, 0x00, 0x08}
	timeHex := encodeBase128(epochtime)
	binaryData = append(binaryData, timeHex...)

	//fmt.Printf(hex.Dump(binaryData))
	buffer.Write(binaryData)

	// Convert buffer to bytes and print as hexadecimal for debugging
	finalData := buffer.Bytes()
	//fmt.Printf("Event Data Hex: %s\n", hex.EncodeToString(finalData))

	return finalData
}

// prepareEventData prepares the event data with custom fields, source, host, sourcetype, an event, and an index name.
func PrepareEventData(fields map[string]string, source, host, sourcetype, indexName, eventContent string, epochtime int64) []byte {
	data := preparePreEventData(source, host, sourcetype, epochtime) // Assume this function is defined elsewhere.
	eventPrefix := []byte("\x04\x05_pathBC:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-winevtlog.exe\x04\x0f_MetaData:Index")

	// The first byte represents the total number of key-value pairs
	result := make([]byte, 1)
	result[0] = byte(2 + len(fields))

	for key, value := range fields {
		// Convert lengths to byte representation
		keyLength := byte(len(key))
		valueLength := byte(len(value))

		// Start the field with the delimiter \x07
		field := []byte{0x07}
		field = append(field, keyLength)
		field = append(field, key...)
		field = append(field, valueLength)
		field = append(field, value...)

		// Append the formatted field to the result
		result = append(result, field...)
	}

	// Append the eventPrefix and the result so far to the data
	finalData := append(data, result...)
	finalData = append(finalData, eventPrefix...)

	// Append the index name length and the index name itself
	indexNameLength := len(indexName)
	finalData = append(finalData, byte(indexNameLength))
	finalData = append(finalData, indexName...)

	// Convert the event content length to a byte slice and append it
	timeHex := encodeBase128(int64(len(eventContent)))
	finalData = append(finalData, timeHex...)

	// Append the actual event content
	finalData = append(finalData, eventContent...)

	return finalData
}

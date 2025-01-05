package tcp

import (
	"bytes"
	"io"
	"iter"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

const (
	ContentTypeHandshake = 0x16

	MessageTypeClientHello = 1

	ExtensionServerName uint16 = 0
)

func filterTLSRecordsOfHandshake(r io.Reader) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for {

			buf := bytes.Buffer{}

			_, err := io.CopyN(&buf, r, 5)
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}

			contentType := buf.Bytes()[0]
			contentLen := int64(buf.Bytes()[3])<<8 | int64(buf.Bytes()[4])

			if contentType != ContentTypeHandshake {
				_, err := io.CopyN(io.Discard, r, contentLen)
				if err != nil {
					if !yield(nil, err) {
						return
					}
				}
				continue // read next record
			}

			_, err = io.CopyN(&buf, r, contentLen)
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}

			if !yield(buf.Bytes()[5:], nil) {
				return
			}
		}
	}
}

func filterTLSClientHelloMessages(r io.Reader) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for handshakeRecord, err := range filterTLSRecordsOfHandshake(r) {
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}

			for len(handshakeRecord) > 4 {

				msgType := handshakeRecord[0]
				msgLen := int(handshakeRecord[1])<<16 | int(handshakeRecord[2])<<8 | int(handshakeRecord[3])

				if msgType != MessageTypeClientHello {
					handshakeRecord = handshakeRecord[4+msgLen:]
					continue
				}

				if !yield(handshakeRecord[4:4+msgLen], nil) {
					return
				}
			}
		}
	}
}

func sniffTLSServerName(rc io.Reader) (serverName string, err error) {

	for clientHelloMsg, err := range filterTLSClientHelloMessages(rc) {
		if err != nil {
			return "", err
		}

		s := cryptobyte.String(clientHelloMsg)

		var (
			ver                uint16
			random             []byte
			sessionID          cryptobyte.String
			cipherSuites       cryptobyte.String
			compressionMethods cryptobyte.String
			extensions         cryptobyte.String
		)

		s.ReadUint16(&ver)
		s.ReadBytes(&random, 32)
		s.ReadUint8LengthPrefixed(&sessionID)
		s.ReadUint16LengthPrefixed(&cipherSuites)
		s.ReadUint8LengthPrefixed(&compressionMethods)
		s.ReadUint16LengthPrefixed(&extensions)

		for !extensions.Empty() {
			var extension uint16
			var extData cryptobyte.String
			extensions.ReadUint16(&extension)
			extensions.ReadUint16LengthPrefixed(&extData)

			if extension == ExtensionServerName {
				// RFC 6066, Section 3
				var nameList cryptobyte.String
				extData.ReadUint16LengthPrefixed(&nameList)

				for !nameList.Empty() {
					var nameType uint8
					var serverName cryptobyte.String
					nameList.ReadUint8(&nameType)
					nameList.ReadUint16LengthPrefixed(&serverName)

					if nameType != 0 {
						continue
					}

					return string(serverName), nil
				}
			}
		}
	}

	return "", nil
}

func ForwardTLS(clientConn *net.TCPConn) {
	SniffHostAndForward(sniffTLSServerName, clientConn)
}

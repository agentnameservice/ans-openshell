package middleware

const (
	bitsPerNibble   = 4
	hexLetterOffset = 10
)

func containsCredentialMarker(value []byte) bool {
	for i, b := range value {
		if b != 'o' && b != 'O' && b != '%' {
			continue
		}
		if encodedPrefix(value[i:], "openshell:resolve:env:") || encodedPrefix(value[i:], "OPENSHELL-RESOLVE-ENV-") {
			return true
		}
	}
	return false
}

func encodedPrefix(value []byte, prefix string) bool {
	for i := range len(prefix) {
		if len(value) == 0 {
			return false
		}
		b := value[0]
		value = value[1:]
		if b == '%' && len(value) >= 2 {
			hi, hiOK := hexDigit(value[0])
			lo, loOK := hexDigit(value[1])
			if hiOK && loOK {
				b = hi<<bitsPerNibble | lo
				value = value[2:]
			}
		}
		if b != prefix[i] {
			return false
		}
	}
	return true
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + hexLetterOffset, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + hexLetterOffset, true
	default:
		return 0, false
	}
}

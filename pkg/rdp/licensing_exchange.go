package rdp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"sync"
)

// The licensing exchange of a Remote Desktop Session Host (MS-RDPELE, ADR-0099, option B): the
// platform challenge and its response, a license issued or upgraded, and, at the next connection,
// the license kept presented again. Per-user mode only: a license lost costs the farm nothing, so
// the cache lives in memory, for the process. Every message from the server is bounded, decrypted
// with RC4 under the licensing encryption key, and its MAC checked before anything of it is used;
// whatever is not exactly what MS-RDPELE allows ends the session, nothing guessed.
//
// RC4, MD5 and SHA-1 are the protocol's (MS-RDPBCGR 5.3.5, 5.3.6.1): imposed by the target, inside
// the TLS channel that already authenticates it, as NTLM's are (ntlmssp_seal.go).

const (
	rdpLicensePlatformChallenge         = byte(0x02)
	rdpLicenseNewLicense                = byte(0x03)
	rdpLicenseUpgradeLicense            = byte(0x04)
	rdpLicenseInfo                      = byte(0x12)
	rdpLicensePlatformChallengeResponse = byte(0x15)

	rdpLicenseBlobData          = uint16(0x0001)
	rdpLicenseBlobEncryptedData = uint16(0x0009)

	// PLATFORM_CHALLENGE_RESPONSE_DATA (MS-RDPELE 2.2.2.5.1): version 1.0, a client of another
	// platform than Win32 (OTHER_PLATFORM_CHALLENGE_TYPE, as FreeRDP says, which Windows accepts),
	// the detailed license level.
	rdpLicenseChallengeVersion     = uint16(0x0100)
	rdpLicenseChallengeClientOther = uint16(0xff00)
	rdpLicenseChallengeDetail      = uint16(0x0003)

	licensingMACSize = 16
	// Bounds of what a server may send: a challenge, and the license it issues.
	maxRDPLicenseChallenge = 1024
	maxRDPLicenseInfo      = 64 << 10
	// A server may challenge once, and once more after a license presented again.
	maxRDPLicensePlatformChallenges = 2
	maxRDPLicenseCacheEntries       = 1024
)

// licensingKeys are the keys of one exchange (MS-RDPBCGR 5.3.5.1, as MS-RDPELE 5.1.3 uses it).
type licensingKeys struct {
	macSalt    [16]byte
	encryption [16]byte
}

func (k *licensingKeys) clear() {
	clear(k.macSalt[:])
	clear(k.encryption[:])
}

// saltedHash is SaltedHash(S, I) = MD5(S + SHA1(I + S + first + second)).
func saltedHash(secret, input, first, second []byte) []byte {
	inner := sha1.New()
	inner.Write(input)
	inner.Write(secret)
	inner.Write(first)
	inner.Write(second)
	outer := md5.New()
	outer.Write(secret)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}

// deriveLicensingKeys: MasterSecret from the premaster secret and both randoms, the
// SessionKeyBlob from it (the randoms in the other order), the MAC salt its first 16 bytes, and the
// licensing encryption key MD5(its next 16 bytes + ClientRandom + ServerRandom).
func deriveLicensingKeys(preMaster, clientRandom, serverRandom []byte) licensingKeys {
	var master, blob []byte
	for _, label := range []string{"A", "BB", "CCC"} {
		master = append(master, saltedHash(preMaster, []byte(label), clientRandom, serverRandom)...)
	}
	for _, label := range []string{"A", "BB", "CCC"} {
		blob = append(blob, saltedHash(master, []byte(label), serverRandom, clientRandom)...)
	}
	var keys licensingKeys
	copy(keys.macSalt[:], blob[:16])
	final := md5.New()
	final.Write(blob[16:32])
	final.Write(clientRandom)
	final.Write(serverRandom)
	copy(keys.encryption[:], final.Sum(nil))
	clear(master)
	clear(blob)
	return keys
}

// licensingMAC is the MAC of MS-RDPBCGR 5.3.6.1: MD5(salt + pad2 + SHA1(salt + pad1 + len + data)).
func licensingMAC(salt [16]byte, data []byte) [licensingMACSize]byte {
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(data)))
	inner := sha1.New()
	inner.Write(salt[:])
	inner.Write(licensingPad(0x36, 40))
	inner.Write(length[:])
	inner.Write(data)
	outer := md5.New()
	outer.Write(salt[:])
	outer.Write(licensingPad(0x5c, 48))
	outer.Write(inner.Sum(nil))
	var mac [licensingMACSize]byte
	copy(mac[:], outer.Sum(nil))
	return mac
}

func licensingPad(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// licensingRC4 encrypts or decrypts one message: a fresh RC4 stream per message, as MS-RDPELE does.
func licensingRC4(key [16]byte, data []byte) []byte {
	stream, err := rc4.NewCipher(key[:])
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out
}

// openLicensingBlob decrypts an encrypted blob of the server and checks the MAC that follows it,
// over the plaintext. A MAC that does not match is a server that does not hold the keys.
func openLicensingBlob(keys licensingKeys, encrypted []byte, mac []byte) ([]byte, bool) {
	if len(mac) != licensingMACSize {
		return nil, false
	}
	plain := licensingRC4(keys.encryption, encrypted)
	want := licensingMAC(keys.macSalt, plain)
	if !hmac.Equal(want[:], mac) {
		clear(plain)
		return nil, false
	}
	return plain, true
}

// licensePreamble reads the licensing message a server packet carries: its type and its body.
func licensePreamble(packet []byte, expectedChannelID uint16) (byte, []byte, bool) {
	userData, err := parseMCSLicensingIndication(packet, expectedChannelID)
	if err != nil || len(userData) < 4+4 {
		return 0, nil, false
	}
	preamble := userData[4:]
	if preamble[1]&0x0f != rdpLicenseProtocolVersion || preamble[1]&0x70 != 0 ||
		int(binary.LittleEndian.Uint16(preamble[2:4])) != len(preamble) {
		return 0, nil, false
	}
	return preamble[0], preamble[4:], true
}

// parseRDPServerPlatformChallenge reads SERVER_PLATFORM_CHALLENGE (MS-RDPELE 2.2.2.4): ConnectFlags,
// the encrypted challenge, its MAC. It returns the challenge, decrypted and checked.
func parseRDPServerPlatformChallenge(body []byte, keys licensingKeys) ([]byte, bool) {
	if len(body) < 4 {
		return nil, false
	}
	_, encrypted, rest, ok := readLicenseBlob(body[4:]) // the blob type is not set by every server
	if !ok || len(encrypted) == 0 || len(encrypted) > maxRDPLicenseChallenge || len(rest) != licensingMACSize {
		return nil, false
	}
	return openLicensingBlob(keys, encrypted, rest)
}

// parseRDPServerNewLicense reads SERVER_NEW_LICENSE and SERVER_UPGRADE_LICENSE (MS-RDPELE 2.2.2.6,
// 2.2.2.7): the encrypted NEW_LICENSE_INFO and its MAC. It returns the license itself
// (pbLicenseInfo), every length of NEW_LICENSE_INFO bounded and consumed exactly.
func parseRDPServerNewLicense(body []byte, keys licensingKeys) ([]byte, bool) {
	typ, encrypted, rest, ok := readLicenseBlob(body)
	if !ok || typ != rdpLicenseBlobEncryptedData || len(encrypted) == 0 || len(rest) != licensingMACSize {
		return nil, false
	}
	plain, ok := openLicensingBlob(keys, encrypted, rest)
	if !ok {
		return nil, false
	}
	defer clear(plain)
	if len(plain) < 4 {
		return nil, false
	}
	info := plain[4:] // dwVersion
	var license []byte
	for i, limit := range []int{maxRDPLicenseStringSize, maxRDPLicenseStringSize, maxRDPLicenseStringSize, maxRDPLicenseInfo} {
		if len(info) < 4 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(info[:4]))
		info = info[4:]
		if n < 0 || n > limit || len(info) < n {
			return nil, false
		}
		if i == 3 {
			if n == 0 {
				return nil, false
			}
			license = append([]byte(nil), info[:n]...)
		}
		info = info[n:]
	}
	if len(info) != 0 {
		clear(license)
		return nil, false
	}
	return license, true
}

// marshalRDPClientPlatformChallengeResponse is CLIENT_PLATFORM_CHALLENGE_RESPONSE (MS-RDPELE
// 2.2.2.5): the response data and the hardware ID, each encrypted, then the MAC over both in clear.
func marshalRDPClientPlatformChallengeResponse(userID, ioChannelID uint16, keys licensingKeys, challenge []byte, hwid [20]byte) ([]byte, error) {
	if len(challenge) == 0 || len(challenge) > maxRDPLicenseChallenge {
		return nil, ErrMCSConnection
	}
	response := make([]byte, 8, 8+len(challenge))
	binary.LittleEndian.PutUint16(response[0:2], rdpLicenseChallengeVersion)
	binary.LittleEndian.PutUint16(response[2:4], rdpLicenseChallengeClientOther)
	binary.LittleEndian.PutUint16(response[4:6], rdpLicenseChallengeDetail)
	binary.LittleEndian.PutUint16(response[6:8], uint16(len(challenge)))
	response = append(response, challenge...)
	defer clear(response)
	macInput := append(append([]byte(nil), response...), hwid[:]...)
	mac := licensingMAC(keys.macSalt, macInput)
	clear(macInput)
	var message []byte
	message = appendLicenseBlob(message, rdpLicenseBlobEncryptedData, licensingRC4(keys.encryption, response))
	message = appendLicenseBlob(message, rdpLicenseBlobEncryptedData, licensingRC4(keys.encryption, hwid[:]))
	message = append(message, mac[:]...)
	return marshalRDPLicenseMessage(userID, ioChannelID, rdpLicensePlatformChallengeResponse, message)
}

// marshalRDPClientLicenseInfo is CLIENT_LICENSE_INFO (MS-RDPELE 2.2.2.3): the license kept,
// presented again with a new premaster secret, the encrypted hardware ID and its MAC.
func marshalRDPClientLicenseInfo(userID, ioChannelID uint16, encryptedPreMaster, clientRandom, license []byte, keys licensingKeys, hwid [20]byte) ([]byte, error) {
	if len(clientRandom) != 32 || len(license) == 0 || len(license) > maxRDPLicenseInfo || len(encryptedPreMaster) == 0 {
		return nil, ErrMCSConnection
	}
	message := make([]byte, 8, 8+32+len(encryptedPreMaster)+len(license)+64)
	binary.LittleEndian.PutUint32(message[0:4], rdpLicenseKeyExchangeRSA)
	binary.LittleEndian.PutUint32(message[4:8], rdpLicensePlatformWinNT)
	message = append(message, clientRandom...)
	message = appendLicenseBlob(message, rdpLicenseBlobRandom, encryptedPreMaster)
	message = appendLicenseBlob(message, rdpLicenseBlobData, license)
	message = appendLicenseBlob(message, rdpLicenseBlobEncryptedData, licensingRC4(keys.encryption, hwid[:]))
	mac := licensingMAC(keys.macSalt, hwid[:])
	message = append(message, mac[:]...)
	return marshalRDPLicenseMessage(userID, ioChannelID, rdpLicenseInfo, message)
}

// marshalRDPLicenseMessage wraps a licensing message in its preamble, the security header and an
// MCS Send Data Request.
func marshalRDPLicenseMessage(userID, ioChannelID uint16, messageType byte, message []byte) ([]byte, error) {
	defer clear(message)
	if !validMCSUserID(userID) || ioChannelID != mcsGlobalChannelID || 4+len(message) > 0xffff {
		return nil, ErrMCSConnection
	}
	preamble := make([]byte, 4, 4+len(message))
	preamble[0] = messageType
	preamble[1] = rdpLicenseProtocolVersion | rdpLicenseExtendedErrors
	binary.LittleEndian.PutUint16(preamble[2:4], uint16(4+len(message)))
	preamble = append(preamble, message...)
	security := make([]byte, 4, 4+len(preamble))
	binary.LittleEndian.PutUint16(security[:2], rdpSecLicensePacket)
	security = append(security, preamble...)
	clear(preamble)
	packet, err := marshalMCSSendDataRequest(userID, ioChannelID, security)
	clear(security)
	if err != nil {
		return nil, ErrMCSConnection
	}
	return packet, nil
}

// LicenseCache keeps the licenses Remote Desktop Session Hosts issued, in memory, for the process
// (ADR-0099, option B): presented again at the next connection to the same target, so that the host
// does not issue another. Per-user mode only — a host in per-device mode counts a license for every
// one this cache loses, at a restart. Its hardware ID is random, drawn once per cache.
type LicenseCache struct {
	mu       sync.Mutex
	licenses map[string][]byte
	hwid     [20]byte
}

// NewLicenseCache returns an empty cache with its own hardware ID.
func NewLicenseCache() (*LicenseCache, error) {
	c := &LicenseCache{licenses: map[string][]byte{}}
	binary.LittleEndian.PutUint32(c.hwid[:4], rdpLicensePlatformWinNT)
	if _, err := io.ReadFull(rand.Reader, c.hwid[4:]); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *LicenseCache) get(scope string) []byte {
	if c == nil || scope == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.licenses[scope]...)
}

func (c *LicenseCache) put(scope string, license []byte) {
	if c == nil || scope == "" || len(license) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.licenses[scope]; !ok && len(c.licenses) >= maxRDPLicenseCacheEntries {
		for k := range c.licenses { // full: one entry goes, any; a license lost is reissued
			delete(c.licenses, k)
			break
		}
	}
	c.licenses[scope] = append([]byte(nil), license...)
}

func (c *LicenseCache) drop(scope string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.licenses, scope)
}

func (c *LicenseCache) hardwareID() [20]byte {
	if c == nil {
		var hwid [20]byte
		binary.LittleEndian.PutUint32(hwid[:4], rdpLicensePlatformWinNT)
		return hwid
	}
	return c.hwid
}

// gen_quic_sni_vectors.go
//
// Generates deterministic QUIC v1 / draft-29 Initial UDP payloads for testing
// passive QUIC SNI sniffers.  The packets are synthetically generated but are
// real QUIC Initial packets: they use QUIC Initial secrets, AES-128-GCM packet
// protection, and AES header protection.
//
// No third-party Go packages are required.
//
// Usage:
//
//	go run gen_quic_sni_vectors.go -out vectors
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	version1       uint32 = 0x00000001
	versionDraft29 uint32 = 0xff00001d

	minInitialDatagram = 1200
)

var (
	quicV1Salt      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicDraft29Salt = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
)

type initialKeys struct {
	key [16]byte
	iv  [12]byte
	hp  [16]byte
}

type vector struct {
	Name    string
	Expect  string
	Domain  string
	Files   []string
	Comment string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u24(v int) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func encVarint(v uint64) []byte {
	switch {
	case v < (1 << 6):
		return []byte{byte(v)}
	case v < (1 << 14):
		x := uint16(v) | 0x4000
		return []byte{byte(x >> 8), byte(x)}
	case v < (1 << 30):
		x := uint32(v) | 0x80000000
		return []byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}
	case v < (1 << 62):
		x := v | 0xc000000000000000
		return []byte{byte(x >> 56), byte(x >> 48), byte(x >> 40), byte(x >> 32), byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}
	default:
		panic("QUIC varint too large")
	}
}

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, outLen int) []byte {
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < outLen {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:outLen]
}

func hkdfExpandLabel(secret []byte, label string, context []byte, outLen int) []byte {
	fullLabel := []byte("tls13 " + label)
	if len(fullLabel) > 255 || len(context) > 255 || outLen > 65535 {
		panic("bad HKDF label")
	}
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(outLen>>8), byte(outLen))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, outLen)
}

func initialSalt(version uint32) []byte {
	switch version {
	case version1:
		return quicV1Salt
	case versionDraft29:
		return quicDraft29Salt
	default:
		panic(fmt.Sprintf("unsupported version %08x", version))
	}
}

func deriveClientInitialKeys(version uint32, dcid []byte) initialKeys {
	salt := initialSalt(version)
	initialSecret := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	key := hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	iv := hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	hp := hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	var k initialKeys
	copy(k.key[:], key)
	copy(k.iv[:], iv)
	copy(k.hp[:], hp)
	return k
}

func makeNonce(iv [12]byte, pn uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, iv[:])
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], pn)
	for i := 0; i < 8; i++ {
		nonce[12-8+i] ^= pnBytes[i]
	}
	return nonce
}

func pnBytes(pn uint64, pnLen int) []byte {
	out := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		shift := uint((pnLen - 1 - i) * 8)
		out[i] = byte(pn >> shift)
	}
	return out
}

func buildInitialPacket(version uint32, dcid, scid, token []byte, pn uint64, pnLen int, plaintextFrames []byte, targetDatagramLen int) []byte {
	if pnLen < 1 || pnLen > 4 {
		panic("bad packet number length")
	}
	if len(dcid) > 20 || len(scid) > 20 {
		panic("connection IDs too long for this generator")
	}

	keys := deriveClientInitialKeys(version, dcid)

	firstByte := byte(0xc0 | byte(pnLen-1)) // long header + fixed bit + Initial + PN length bits
	headerPrefix := make([]byte, 0, 64)
	headerPrefix = append(headerPrefix, firstByte)
	headerPrefix = append(headerPrefix, u32(version)...)
	headerPrefix = append(headerPrefix, byte(len(dcid)))
	headerPrefix = append(headerPrefix, dcid...)
	headerPrefix = append(headerPrefix, byte(len(scid)))
	headerPrefix = append(headerPrefix, scid...)
	headerPrefix = append(headerPrefix, encVarint(uint64(len(token)))...)
	headerPrefix = append(headerPrefix, token...)

	plain := append([]byte(nil), plaintextFrames...)
	if targetDatagramLen > 0 {
		for {
			lengthValue := uint64(pnLen + len(plain) + 16) // packet number + ciphertext + tag
			lenField := encVarint(lengthValue)
			total := len(headerPrefix) + len(lenField) + pnLen + len(plain) + 16
			if total >= targetDatagramLen {
				break
			}
			plain = append(plain, make([]byte, targetDatagramLen-total)...)
		}
	}

	lengthValue := uint64(pnLen + len(plain) + 16)
	lenField := encVarint(lengthValue)
	header := make([]byte, 0, len(headerPrefix)+len(lenField)+pnLen)
	header = append(header, headerPrefix...)
	header = append(header, lenField...)
	pnOffset := len(header)
	header = append(header, pnBytes(pn, pnLen)...)

	block, err := aes.NewCipher(keys.key[:])
	must(err)
	gcm, err := cipher.NewGCM(block)
	must(err)

	nonce := makeNonce(keys.iv, pn)
	ciphertextAndTag := gcm.Seal(nil, nonce, plain, header)

	packet := append(append([]byte(nil), header...), ciphertextAndTag...)

	// QUIC header protection sample starts 4 bytes after PN offset, regardless
	// of the actual packet-number length.
	if len(packet) < pnOffset+4+16 {
		panic("packet too small for header protection sample")
	}
	sample := packet[pnOffset+4 : pnOffset+4+16]
	hpBlock, err := aes.NewCipher(keys.hp[:])
	must(err)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	packet[0] ^= mask[0] & 0x0f // long header: only low 4 bits are masked
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[i+1]
	}

	return packet
}

func cryptoFrame(offset uint64, data []byte) []byte {
	out := []byte{0x06}
	out = append(out, encVarint(offset)...)
	out = append(out, encVarint(uint64(len(data)))...)
	out = append(out, data...)
	return out
}

func pingFrame() []byte { return []byte{0x01} }

func paddingFrame(n int) []byte {
	if n < 0 {
		panic("negative padding")
	}
	return make([]byte, n) // PADDING frame is byte 0x00 repeated
}

func ext(extType uint16, body []byte) []byte {
	out := append(u16(extType), u16(uint16(len(body)))...)
	out = append(out, body...)
	return out
}

func sniExt(domain string) []byte {
	name := []byte(domain)
	entry := []byte{0x00}
	entry = append(entry, u16(uint16(len(name)))...)
	entry = append(entry, name...)
	list := append(u16(uint16(len(entry))), entry...)
	return ext(0x0000, list)
}

func alpnExt(protocols ...string) []byte {
	var list []byte
	for _, p := range protocols {
		if len(p) > 255 {
			panic("ALPN too long")
		}
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	body := append(u16(uint16(len(list))), list...)
	return ext(0x0010, body)
}

func supportedVersionsExt() []byte {
	return ext(0x002b, []byte{0x02, 0x03, 0x04}) // TLS 1.3
}

func supportedGroupsExt() []byte {
	groups := []byte{0x00, 0x1d} // x25519
	body := append(u16(uint16(len(groups))), groups...)
	return ext(0x000a, body)
}

func signatureAlgorithmsExt() []byte {
	algs := []byte{
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
	}
	body := append(u16(uint16(len(algs))), algs...)
	return ext(0x000d, body)
}

func keyShareExt() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	entry := []byte{0x00, 0x1d} // x25519
	entry = append(entry, u16(uint16(len(key)))...)
	entry = append(entry, key...)
	body := append(u16(uint16(len(entry))), entry...)
	return ext(0x0033, body)
}

func quicTransportParamsExt() []byte {
	// Empty transport-parameter sequence.  This is enough for SNI parser tests;
	// real QUIC stacks would usually send several parameters.
	return ext(0x0039, nil)
}

func fakeECHOuterExt() []byte {
	// Not a real ECH extension; this is only to make sure a sniffer does not
	// crash or mistake unknown extensions for SNI.
	return ext(0xfe0d, []byte{0x00, 0x01, 0x02, 0x03, 0xaa, 0xbb, 0xcc, 0xdd})
}

func unknownExt(extType uint16, size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte((i*31 + int(extType)) & 0xff)
	}
	return ext(extType, body)
}

func clientHello(domain string, withSNI bool, addFakeECH bool, largeBeforeSNI int) []byte {
	var exts []byte
	exts = append(exts, supportedVersionsExt()...)
	exts = append(exts, supportedGroupsExt()...)
	exts = append(exts, signatureAlgorithmsExt()...)
	exts = append(exts, keyShareExt()...)
	exts = append(exts, alpnExt("h3")...)
	exts = append(exts, quicTransportParamsExt()...)
	if largeBeforeSNI > 0 {
		exts = append(exts, unknownExt(0xaaaa, largeBeforeSNI)...)
	}
	if withSNI {
		exts = append(exts, sniExt(domain)...)
	}
	if addFakeECH {
		exts = append(exts, fakeECHOuterExt()...)
	}

	body := make([]byte, 0, 256+len(exts))
	body = append(body, 0x03, 0x03) // legacy_version
	for i := 0; i < 32; i++ {
		body = append(body, byte(i+1))
	}
	body = append(body, 0x00)                // legacy_session_id length
	suites := []byte{0x13, 0x01, 0x13, 0x02} // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
	body = append(body, u16(uint16(len(suites)))...)
	body = append(body, suites...)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, u16(uint16(len(exts)))...)
	body = append(body, exts...)

	hs := []byte{0x01} // ClientHello
	hs = append(hs, u24(len(body))...)
	hs = append(hs, body...)
	return hs
}

func writeFile(dir, name string, data []byte) string {
	path := filepath.Join(dir, name)
	must(os.WriteFile(path, data, 0644))
	return name
}

func splitAtDomainMiddle(ch []byte, domain string) (int, int) {
	idx := strings.Index(string(ch), domain)
	if idx < 0 {
		panic("domain not found in ClientHello")
	}
	return idx + len(domain)/2, idx
}

func main() {
	outDir := flag.String("out", "vectors", "output directory")
	flag.Parse()

	must(os.MkdirAll(*outDir, 0755))

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x44, 0x55, 0x66, 0x77}

	var vectors []vector

	add := func(name, expect, domain, comment string, files ...string) {
		vectors = append(vectors, vector{Name: name, Expect: expect, Domain: domain, Files: files, Comment: comment})
	}

	// 01: basic one-packet ClientHello + SNI.
	{
		domain := "basic.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "01_single_initial.bin", pkt)
		add("single_initial", "OK", domain, "Complete ClientHello/SNI in one QUIC v1 Initial packet.", f)
	}

	// 02: ClientHello split across two UDP datagrams; split inside the hostname.
	{
		domain := "split-inside-host.example"
		ch := clientHello(domain, true, false, 0)
		split, _ := splitAtDomainMiddle(ch, domain)
		p0 := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch[:split]), minInitialDatagram)
		p1 := buildInitialPacket(version1, dcid, scid, nil, 1, 1, cryptoFrame(uint64(split), ch[split:]), minInitialDatagram)
		f0 := writeFile(*outDir, "02_split_inside_host_part1.bin", p0)
		f1 := writeFile(*outDir, "02_split_inside_host_part2.bin", p1)
		add("split_inside_hostname_two_datagrams", "OK", domain, "Feed part1 first: sniffer should need more. Feed part2: SNI should appear. Split is inside hostname bytes.", f0, f1)
	}

	// 03: Same split as above, but coalesced into one UDP payload.
	{
		domain := "coalesced.example"
		ch := clientHello(domain, true, false, 0)
		split, _ := splitAtDomainMiddle(ch, domain)
		p0 := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch[:split]), 0)
		p1Target := minInitialDatagram - len(p0)
		if p1Target < 0 {
			p1Target = 0
		}
		p1 := buildInitialPacket(version1, dcid, scid, nil, 1, 1, cryptoFrame(uint64(split), ch[split:]), p1Target)
		coalesced := append(append([]byte(nil), p0...), p1...)
		f := writeFile(*outDir, "03_coalesced_two_initials.bin", coalesced)
		add("coalesced_two_initial_packets", "OK", domain, "One UDP payload containing two protected Initial packets; sniffer must loop over coalesced packets.", f)
	}

	// 04: Non-CRYPTO frames and padding before CRYPTO.
	{
		domain := "padding-ping.example"
		ch := clientHello(domain, true, false, 0)
		frames := append([]byte{}, paddingFrame(17)...)
		frames = append(frames, pingFrame()...)
		frames = append(frames, paddingFrame(9)...)
		frames = append(frames, cryptoFrame(0, ch)...)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, frames, minInitialDatagram)
		f := writeFile(*outDir, "04_padding_ping_before_crypto.bin", pkt)
		add("padding_ping_before_crypto", "OK", domain, "Initial payload starts with PADDING and PING before the CRYPTO frame.", f)
	}

	// 05: 4-byte packet number length.
	{
		domain := "pnlen4.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0x01020304, 4, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "05_packet_number_length_4.bin", pkt)
		add("packet_number_length_4", "OK", domain, "Valid Initial with 4-byte packet number; catches sniffers that only accept 1-byte PN.", f)
	}

	// 06: Retry-style token present.
	{
		domain := "token.example"
		ch := clientHello(domain, true, false, 0)
		token, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718")
		pkt := buildInitialPacket(version1, dcid, scid, token, 0, 2, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "06_initial_with_token.bin", pkt)
		add("initial_with_token", "OK", domain, "Client Initial with non-empty token field and 2-byte packet number.", f)
	}

	// 07: Two CRYPTO frames in one packet.
	{
		domain := "two-crypto-frames.example"
		ch := clientHello(domain, true, false, 0)
		n := len(ch) / 2
		frames := append([]byte{}, cryptoFrame(0, ch[:n])...)
		frames = append(frames, pingFrame()...)
		frames = append(frames, cryptoFrame(uint64(n), ch[n:])...)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, frames, minInitialDatagram)
		f := writeFile(*outDir, "07_two_crypto_frames_same_packet.bin", pkt)
		add("two_crypto_frames_same_packet", "OK", domain, "ClientHello split across two CRYPTO frames inside the same Initial packet.", f)
	}

	// 08: Out-of-order CRYPTO frame offsets in one packet.
	{
		domain := "out-of-order.example"
		ch := clientHello(domain, true, false, 0)
		n := len(ch) / 2
		frames := append([]byte{}, cryptoFrame(uint64(n), ch[n:])...)
		frames = append(frames, pingFrame()...)
		frames = append(frames, cryptoFrame(0, ch[:n])...)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, frames, minInitialDatagram)
		f := writeFile(*outDir, "08_out_of_order_crypto_offsets.bin", pkt)
		add("out_of_order_crypto_offsets", "OK", domain, "CRYPTO stream data arrives with higher offset before offset 0; reassembly must be offset-based.", f)
	}

	// 09: Large unknown extension before SNI, split at offset > 63 to force multi-byte CRYPTO offset varints.
	{
		domain := "large-offset.example"
		ch := clientHello(domain, true, false, 300)
		split := 180
		p0 := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch[:split]), minInitialDatagram)
		p1 := buildInitialPacket(version1, dcid, scid, nil, 1, 1, cryptoFrame(uint64(split), ch[split:]), minInitialDatagram)
		f0 := writeFile(*outDir, "09_large_offset_part1.bin", p0)
		f1 := writeFile(*outDir, "09_large_offset_part2.bin", p1)
		add("large_offset_varint_split", "OK", domain, "Second CRYPTO offset is >63, requiring a multi-byte QUIC varint. Also puts a large extension before SNI.", f0, f1)
	}

	// 10: draft-29 salt and version.
	{
		domain := "draft29.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(versionDraft29, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "10_draft29_initial.bin", pkt)
		add("draft29_initial", "OK", domain, "QUIC draft-29 Initial using the draft-29 Initial salt.", f)
	}

	// 11: no SNI in ClientHello.
	{
		ch := clientHello("", false, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "11_no_sni.bin", pkt)
		add("no_sni_clienthello", "NO_SNI", "", "Valid ClientHello without server_name extension.", f)
	}

	// 12: fake ECH-like unknown extension with outer SNI.
	{
		domain := "outer.example"
		ch := clientHello(domain, true, true, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		f := writeFile(*outDir, "12_fake_ech_outer_sni.bin", pkt)
		add("fake_ech_outer_sni", "OK", domain, "Contains SNI plus an unknown fake ECH-like extension; real ECH would hide the private name.", f)
	}

	// 13: truncated packet should need more or fail as truncated, but never report OK.
	{
		domain := "truncated.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		trunc := pkt[:len(pkt)/2]
		f := writeFile(*outDir, "13_truncated_initial.bin", trunc)
		add("truncated_initial", "NEED_MORE_OR_FAIL", "", "Half of a valid Initial packet; sniffer must not report a domain.", f)
	}

	// 14: corrupt authentication tag/ciphertext should not decrypt.
	{
		domain := "badtag.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		pkt[len(pkt)-1] ^= 0x55
		f := writeFile(*outDir, "14_bad_gcm_tag.bin", pkt)
		add("bad_gcm_tag", "FAIL", "", "Ciphertext/tag corrupted; sniffer must not return a domain.", f)
	}

	// 15: unsupported QUIC version with otherwise parseable-looking long header.
	{
		domain := "unsupported.example"
		ch := clientHello(domain, true, false, 0)
		pkt := buildInitialPacket(version1, dcid, scid, nil, 0, 1, cryptoFrame(0, ch), minInitialDatagram)
		// After header protection, version bytes remain unprotected at bytes 1..4.
		binary.BigEndian.PutUint32(pkt[1:5], 0x0a0a0a0a)
		f := writeFile(*outDir, "15_unsupported_version.bin", pkt)
		add("unsupported_version", "UNSUPPORTED_OR_FAIL", "", "Version field changed after encryption; v1-only sniffer should reject, not sniff.", f)
	}

	manifest := &strings.Builder{}
	fmt.Fprintln(manifest, "# name|expect|domain|files_csv|comment")
	for _, v := range vectors {
		fmt.Fprintf(manifest, "%s|%s|%s|%s|%s\n", v.Name, v.Expect, v.Domain, strings.Join(v.Files, ","), v.Comment)
	}
	must(os.WriteFile(filepath.Join(*outDir, "manifest.txt"), []byte(manifest.String()), 0644))

	fmt.Printf("wrote %d test vectors to %s\n", len(vectors), *outDir)
}

package sm4

var fk = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

func expand(key [4]uint32) [4]uint32 {
	var k [4]uint32
	for i := range k {
		k[i] = key[i] ^ fk[i]
	}
	return k
}

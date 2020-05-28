package aescbc

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/fallinginmyhand/paddingworker"
)

// AESCBCenc AES CBC enc
func AESCBCenc(src []byte, key []byte, iv []byte, blkSize int) []byte {

	padsrc, newlen := paddingworker.PCKS(src, blkSize)
	blk, _ := aes.NewCipher(key)
	ensrc := make([]byte, newlen)
	mode := cipher.NewCBCEncrypter(blk, iv)
	mode.CryptBlocks(ensrc, padsrc)
	return ensrc
}

// AESCBCdec AES CBC dec
func AESCBCdec(src []byte, key []byte, iv []byte, blkSize int) []byte {

	blk, _ := aes.NewCipher(key)
	ensrc := make([]byte, len(src))
	mode := cipher.NewCBCDecrypter(blk, iv)
	mode.CryptBlocks(ensrc, src)
	rt := paddingworker.RemovePadding(ensrc, blkSize)
	return rt
}

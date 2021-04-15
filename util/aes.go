package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

/*
 * Copyright 1999-2020 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

func ECBEncrypt(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = PKCS5Padding(src, block.BlockSize())
	encryptData := make([]byte, len(src))
	ecb := NewECBEncryptEr(block)
	ecb.CryptBlocks(encryptData, src)
	return encryptData, nil
}

func ECBDecrypt(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	mode := NewECBDecryptEr(block)
	mode.CryptBlocks(dst, src)
	dst = PKCS5UnPadding(dst)
	return dst, nil
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncryptEr ecb

func NewECBEncryptEr(b cipher.Block) cipher.BlockMode {
	return (*ecbEncryptEr)(newECB(b))
}

func (x *ecbEncryptEr) BlockSize() int { return x.blockSize }

func (x *ecbEncryptEr) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecryptEr ecb

func NewECBDecryptEr(b cipher.Block) cipher.BlockMode {
	return (*ecbDecryptEr)(newECB(b))
}

func (x *ecbDecryptEr) BlockSize() int { return x.blockSize }

func (x *ecbDecryptEr) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	return PKCS5Padding(src, blockSize)
}

func PKCS7UnPadding(src []byte) []byte {
	return PKCS5UnPadding(src)
}

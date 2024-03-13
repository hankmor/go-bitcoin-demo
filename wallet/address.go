package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func main() {
	// createAndRestoreTaprootAddr()

	pkFromUnisat, addrFromUnisat := "d08df378a0a383c196d3629e9f09b58ea3121fc0abef4363d23bc60529455b9b", "tb1p43pf9mnr26g5446jel8z8jy9ldhxp6rqvm3r6ewg4yrnk6lcsf8qwv3s6m"
	testRestorePrivateKey(pkFromUnisat, addrFromUnisat)
	pkFromUnisat, addrFromUnisat = "cUa71DQn1hhZUoa3wzdibbgM1DCiheZnxkDyKthNxvFuy8bAuc9J", "tb1p43pf9mnr26g5446jel8z8jy9ldhxp6rqvm3r6ewg4yrnk6lcsf8qwv3s6m"
	testRestorePrivateKeyWIF(pkFromUnisat, addrFromUnisat)
}

// 创建和导入Taproot地址
func createAndRestoreTaprootAddr() {
	// 公共比特币网络的网络参数。
	// 该网络有时被简单地称为 "signet "或 "taproot signet"。
	// 网络有时简单地称为 "signet "或 "taproot signet"。
	netParams := &chaincfg.SigNetParams
	// 创建私钥
	prk, err := btcec.NewPrivateKey()
	if err != nil {
		panic(fmt.Errorf("create private key error: %v", err))
	}
	// 转换为hex
	prkHex := hex.EncodeToString(prk.Serialize())
	fmt.Printf("private key: %s\n", prkHex)

	// 创建 taproot 公钥地址
	taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(prk.PubKey())), netParams)

	if err != nil {
		panic(fmt.Errorf("create taproot address error: %v", err))
	}
	fmt.Printf("taproot address: %s\n", taprootAddr)
	// private key: f5673e5352ce99aad5ece033e5c65ad6f1afd3d0b77964e2af04afb35abee4c7
	// taproot address: tb1pdr3jr58mp6qxy05yflp57665vxu04hlmcsvs8h0vkzfe94l87qssa7huqm

	// 重新加载私钥
	restorePrivateKeyBytes, err := hex.DecodeString(prkHex)
	if err != nil {
		panic(err)
	}

	restorePrivateKey, _ := btcec.PrivKeyFromBytes(restorePrivateKeyBytes)
	restoreTaprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(restorePrivateKey.PubKey())), netParams)
	if err != nil {
		panic(err)
	}

	fmt.Printf("restored taproot addr: %s\n", restoreTaprootAddr.EncodeAddress())

	if taprootAddr.EncodeAddress() == restoreTaprootAddr.EncodeAddress() {
		fmt.Println("success")
	} else {
		fmt.Println("error: restored private key does not match")
	}
}

// 导入私钥
func testRestorePrivateKey(pk string, expectAddr string) {
	// 测试网络
	netParams := &chaincfg.TestNet3Params
	// 解码
	restorePrivateKeyBytes, err := hex.DecodeString(pk)
	if err != nil {
		panic(err)
	}

	// 加载私钥
	restorePrivateKey, _ := btcec.PrivKeyFromBytes(restorePrivateKeyBytes)
	// 生成地址
	restoreTaprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(restorePrivateKey.PubKey())), netParams)
	if err != nil {
		panic(err)
	}

	fmt.Printf("restored taproot addr: %s\n", restoreTaprootAddr.EncodeAddress())

	if restoreTaprootAddr.EncodeAddress() == expectAddr {
		fmt.Println("success")
	} else {
		fmt.Println("error, not match")
	}
}

// 导入WIF格式的私钥
func testRestorePrivateKeyWIF(wifpk string, expectAddr string) {
	// 测试网络
	netParams := &chaincfg.TestNet3Params
	// 解码
	wif, _ := btcutil.DecodeWIF(wifpk)

	// 加载私钥
	restorePrivateKey, _ := btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())

	// 生成公钥
	pubKey := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(restorePrivateKey.PubKey()))
	// 生成地址
	restoreTaprootAddr, err := btcutil.NewAddressTaproot(pubKey, netParams)
	if err != nil {
		panic(err)
	}
	fmt.Printf("restored taproot addr: %s\n", restoreTaprootAddr.EncodeAddress())

	if restoreTaprootAddr.EncodeAddress() == expectAddr {
		fmt.Println("success")
	} else {
		fmt.Println("error, not match")
	}
}

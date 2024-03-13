package mempool

import (
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"testing"
)

func TestListUnspent(t *testing.T) {
	// https://mempool.space/signet/api/address/tb1p8lh4np5824u48ppawq3numsm7rss0de4kkxry0z70dcfwwwn2fcspyyhc7/utxo
	netParams := &chaincfg.TestNet3Params
	client := NewClient(netParams)
	address, _ := btcutil.DecodeAddress("tb1pja2cxxa3wmwpmce4jpdmhv3ulxhe9h2nqdglvv69z2c56eljhw9s3mn9tz", netParams)
	unspentList, err := client.ListUnspent(address)
	if err != nil {
		t.Error(err)
	} else {
		t.Log(len(unspentList))
		for _, output := range unspentList {
			fmt.Println(output.Outpoint.Hash.String(), "    ", output.Outpoint.Index)
		}
	}
}

func TestListTxs(t *testing.T) {
	netParams := &chaincfg.SigNetParams
	client := NewClient(netParams)
	address, _ := btcutil.DecodeAddress("bc1p4rn484yaqxtfp0ytdwxd0ygdyhfqv75zvf7pwyl39xzucsel53qqdahgv5", netParams)
	txs, err := client.ListTxs(address)
	if err != nil {
		panic(err)
	}
	fmt.Println(txs)
}

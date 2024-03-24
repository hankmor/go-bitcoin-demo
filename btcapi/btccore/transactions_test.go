package btccore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"hankmo.com/btcdemo/security"
	"log"
	"testing"
)

func TestGetRawTransaction(t *testing.T) {
	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         "10.10.10.207:18332",
		Endpoint:     "",
		User:         security.GetUser(),
		Pass:         security.GetPwd(),
		DisableTLS:   true,
		HTTPPostMode: true,
	}, nil)
	if err != nil {
		log.Fatal(err)
	}
	txId, _ := chainhash.NewHashFromStr("467b77fe181e73e3e4d23a86af4eba2ef9a56eac123587879ba330ee13009d41")
	tx, err := client.GetRawTransaction(txId)
	fmt.Println(tx.Hash())
	var buf bytes.Buffer
	tx.MsgTx().Serialize(&buf)
	r, err := client.DecodeRawTransaction(buf.Bytes())
	bs, err := json.Marshal(r)
	fmt.Println(string(bs))
}

package btccore

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"hankmo.com/btcdemo/btcapi"
)

func (c *Client) ListUnspent(address btcutil.Address) ([]*btcapi.UnspentOutput, error) {
	unspentOutputs, err := c.C.ListUnspentMinMaxAddresses(0, 100, []btcutil.Address{address})
	if err != nil {
		return nil, err
	}
	var utxos []*btcapi.UnspentOutput
	for _, output := range unspentOutputs {
		pubScript, err := hex.DecodeString(output.ScriptPubKey)
		if err != nil {
			return nil, err
		}
		hash, err := chainhash.NewHashFromStr(output.TxID)
		utxos = append(utxos, &btcapi.UnspentOutput{
			Outpoint: wire.NewOutPoint(hash, output.Vout),
			Output:   wire.NewTxOut(int64(output.Amount), pubScript),
		})
	}
	return utxos, nil
}

func (c *Client) ListTxs(address btcutil.Address) ([]*wire.MsgTx, error) {
	msgTxs, err := c.ListTxs(address)
	if err != nil {
		return nil, err
	}
	return msgTxs, nil
}

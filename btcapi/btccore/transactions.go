package btccore

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func (c *Client) GetRawTransaction(txHash *chainhash.Hash) (*wire.MsgTx, error) {
	tx, err := c.GetRawTransaction(txHash)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (c *Client) GetHashedTransaction(txHash *chainhash.Hash) (*wire.MsgTx, error) {
	tx, err := c.GetHashedTransaction(txHash)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (c *Client) BroadcastTx(tx *wire.MsgTx) (*chainhash.Hash, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	txHash, err := c.BroadcastTx(tx)
	if err != nil {
		return nil, err
	}
	return txHash, nil
}

package btccore

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"hankmo.com/btcdemo/btcapi"
	"hankmo.com/btcdemo/security"
	"io"
	"log"
)

type Client struct {
	Host string
	Port int
	User string
	Pwd  string
	C    *rpcclient.Client
}

func NewClient(netParams *chaincfg.Params, user, pwd string) *Client {
	rpcClient, err := rpcclient.New(&rpcclient.ConnConfig{
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
	return &Client{
		C: rpcClient,
	}
}

func (c *Client) request(method, subPath string, requestBody io.Reader) ([]byte, error) {
	return btcapi.RequestAuth(method, c.baseURL, subPath, c.User, c.Pwd, requestBody)
}

var _ btcapi.BTCAPIClient = (*Client)(nil)

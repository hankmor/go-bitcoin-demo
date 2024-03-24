package ord

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"hankmo.com/btcdemo/security"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"hankmo.com/btcdemo/btcapi/mempool"
)

func TestInscribe(t *testing.T) {
	// 创建api client
	net := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(net)

	// 读取被铭刻的图片文件
	workingDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory, %v", err)
	}
	//file := "1.jpeg"
	file := "2.jpg"
	filePath := fmt.Sprintf("%s/%s", workingDir, file)
	// if file size too max will return sendrawtransaction RPC error: {"code":-26,"message":"tx-size"}
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file %v", err)
	}
	// 读取文件 content type
	contentType := http.DetectContentType(fileContent)
	log.Printf("file contentType %s", contentType)

	// 私钥，后边铭刻需要用来签名
	utxoPrivateKeyHex := security.GetPrivateKey()
	// 接收铭文的地址
	destination := os.Getenv("addr")

	// 从私钥生成taproot地址
	utxoPrivateKeyBytes, err := hex.DecodeString(utxoPrivateKeyHex)
	if err != nil {
		log.Fatal(err)
	}
	utxoPrivateKey, _ := btcec.PrivKeyFromBytes(utxoPrivateKeyBytes)

	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(utxoPrivateKey.PubKey())), net)
	if err != nil {
		log.Fatal(err)
	}

	// 查询地址的UTXO
	unspentList, err := btcApiClient.ListUnspent(utxoTaprootAddress)
	if err != nil {
		log.Fatalf("list unspent err %v", err)
	}

	// 从UTXO 中找到 output
	commitTxOutPointList := make([]*wire.OutPoint, 0)
	commitTxPrivateKeyList := make([]*btcec.PrivateKey, 0)
	for i := range unspentList {
		commitTxOutPointList = append(commitTxOutPointList, unspentList[i].Outpoint)
		commitTxPrivateKeyList = append(commitTxPrivateKeyList, utxoPrivateKey)
	}

	// 构建铭刻请求
	request := InscriptionRequest{
		CommitTxOutPointList:   commitTxOutPointList,   // 预提交花费的output
		CommitTxPrivateKeyList: commitTxPrivateKeyList, // 预提交时的私钥
		CommitFeeRate:          2,                      // 预提交费率
		FeeRate:                1,                      // 最终铭刻的费率
		DataList: []InscriptionData{
			{
				ContentType: contentType, // 铭文的content type
				Body:        fileContent, // 铭文的数据，这里是文件
				Destination: destination, // 接收铭文的目标地址
			},
		},
		SingleRevealTxOnly: false,
	}

	// 铭刻
	tool, err := NewInscriptionToolWithBtcApiClient(net, btcApiClient, &request)
	if err != nil {
		log.Fatalf("Failed to create inscription tool: %v", err)
	}
	commitTxHash, revealTxHashList, inscriptions, fees, err := tool.Inscribe()
	if err != nil {
		log.Fatalf("send tx errr, %v", err)
	}
	log.Println("commitTxHash, " + commitTxHash.String())
	for i := range revealTxHashList {
		log.Println("revealTxHash, " + revealTxHashList[i].String())
	}
	for i := range inscriptions {
		log.Println("inscription, " + inscriptions[i])
	}
	log.Println("fees: ", fees)

	//2024/03/11 22:52:29 file contentType image/jpeg
	//2024/03/11 23:03:44 commitTxHash, ae165c500e40128851a62f6a393f49a29ca05090f4e8d48e7bef53dad451005d
	//2024/03/11 23:03:49 revealTxHash, d2eff33bbddc5c87bc40e404ee719dcd39df587ed5c22007d23f914272b9a946
	//2024/03/11 23:03:51 inscription, d2eff33bbddc5c87bc40e404ee719dcd39df587ed5c22007d23f914272b9a946i0
	//2024/03/11 23:03:53 fees:  36583

	//2024/03/11 23:41:39 file contentType image/png
	//2024/03/11 23:41:42 commitTxHash, fe138a9d04d2b9468709de786bf37d827393ec3462376d17678d4eaf0d149814
	//2024/03/11 23:41:42 revealTxHash, ffdaf566807afd75dd1d75a8de04a61f6846fa7169c399e97033a3b89521ab2e
	//2024/03/11 23:41:42 inscription, ffdaf566807afd75dd1d75a8de04a61f6846fa7169c399e97033a3b89521ab2ei0
	//2024/03/11 23:41:42 fees:  2336
}

func TestTransfer(t *testing.T) {
	// 创建api client
	net := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(net)

	// 私钥
	senderPrivateKey := security.GetPrivateKey()
	// 接收地址
	recvAddr := "tb1pja2cxxa3wmwpmce4jpdmhv3ulxhe9h2nqdglvv69z2c56eljhw9s3mn9tz" // os.Getenv("addr")

	var utxos []string
	// 选择需要用到的UTXO，而不是全部
	inscriptionTxid := "759289e93a08da9c52510ad3bc0fbc0de6c43d095a2dca4d4e468f452f6067a7"
	feeTxid := "ea3a8473cd0c182db6accd64a3035a0ea81388144f4f0c82063bb569ee8aa3b6"
	utxos = append(utxos, inscriptionTxid)
	utxos = append(utxos, feeTxid)
	tool, err := NewInscriptionToolWithBtcApiClient(net, btcApiClient, nil)
	txHash, err := tool.SpendUXTO(senderPrivateKey, utxos, recvAddr, 1, 3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(txHash.String())
}

func TestQueryUTXO(t *testing.T) {
	net := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(net)
	senderPrivateKey := security.GetPrivateKey()
	pkBytes, err := hex.DecodeString(senderPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	utxoPrivateKey, _ := btcec.PrivKeyFromBytes(pkBytes)
	senderAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(utxoPrivateKey.PubKey())), net)
	utxos, err := btcApiClient.ListUnspent(senderAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, utxo := range utxos {
		fmt.Println(utxo.Outpoint.String())
	}
}

func TestPublicKeyAndPrivateKey(t *testing.T) {
	addr := os.Getenv("addr")
	net := &chaincfg.TestNet3Params
	pk := security.GetPrivateKey()
	utxoPrivateKeyBytes, err := hex.DecodeString(pk)
	if err != nil {
		log.Fatal(err)
	}
	_, publicKey := btcec.PrivKeyFromBytes(utxoPrivateKeyBytes)
	utxoTaprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(publicKey)), net)
	fmt.Println(utxoTaprootAddress.EncodeAddress())
	fmt.Println(addr == utxoTaprootAddress.EncodeAddress()) // true
}

func TestQueryInscription(t *testing.T) {
	inscriptionId := "a85846a4fa5ba6d1ce4f9a5f70956e9f060c409eba7c18279e19192311476de6i0"
	base := "https://ordinalscan.net/"
	uri := "/api/inscriptions/%s"
	url := base + fmt.Sprintf(uri, inscriptionId)
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	bs, err := io.ReadAll(resp.Body)
	fmt.Println(string(bs))
}

func TestQueryInscriptionFromUnisat(t *testing.T) {
	inscriptionId := "a85846a4fa5ba6d1ce4f9a5f70956e9f060c409eba7c18279e19192311476de6i0"
	base := "https://open-api.unisat.io"
	uri := "/v1/indexer/inscription/info/%s"
	url := base + fmt.Sprintf(uri, inscriptionId)
	client := http.DefaultClient
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer ")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	bs, err := io.ReadAll(resp.Body)
	fmt.Println(string(bs))
}

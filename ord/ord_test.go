package ord

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
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
	utxoPrivateKeyHex := os.Getenv("pk")
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

func TestInscribeChild(t *testing.T) {
	// 创建api client
	net := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(net)

	// 父铭文id
	parentInscriptionId := "ffdaf566807afd75dd1d75a8de04a61f6846fa7169c399e97033a3b89521ab2ei0"

	// 私钥，后边铭刻需要用来签名
	utxoPrivateKeyHex := os.Getenv("pk")
	// 接收铭文的地址
	destination := os.Getenv("addr")

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
				ParentId:    parentInscriptionId,
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
		fmt.Println("revealTxHash, " + revealTxHashList[i].String())
	}
	for i := range inscriptions {
		fmt.Println("inscription, " + inscriptions[i])
	}
	fmt.Println("fees: ", fees)
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

func TestName(t *testing.T) {
	height := 834325
	// 每210_000个区块奖励减半，所以可以直接查询处指定区块高度当前的奖励
	var d = (50 * 100_000_000) >> (height / 210_000)
	fmt.Println(d)
}

func TestIntToBytes(t *testing.T) {
	a := 255
	fmt.Println(intToBytesLE(int32(a)))
	fmt.Println(strconv.FormatInt(int64(a), 16))
	a = 256
	fmt.Println(intToBytesLE(int32(a)))
	fmt.Println(strconv.FormatInt(int64(a), 16))
	a = 257
	fmt.Println(intToBytesLE(int32(a)))
	fmt.Println(strconv.FormatInt(int64(a), 16))
	// [255 0 0 0]
	// ff
	// [0 1 0 0]
	// 100
	// [1 1 0 0]
	// 101
}

func TestParseInscriptionHexId(t *testing.T) {
	s := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi0"
	txid, bs, err := ParseInscriptionHexId(s)
	if err != nil {
		t.Fatal("test failed: ", err)
	}
	assert.Equal(t, txid, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	assert.Equal(t, hex.EncodeToString(bs), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
	s = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi255"
	txid, bs, err = ParseInscriptionHexId(s)
	if err != nil {
		t.Fatal("test failed: ", err)
	}
	assert.Equal(t, txid, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	assert.Equal(t, hex.EncodeToString(bs), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100ff")
	s = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi256"
	txid, bs, err = ParseInscriptionHexId(s)
	if err != nil {
		t.Fatal("test failed: ", err)
	}
	assert.Equal(t, txid, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	assert.Equal(t, hex.EncodeToString(bs), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201000001")
}

func TestRevert(t *testing.T) {
	s := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	bs, _ := hex.DecodeString(s)
	size := len(bs)
	for i := 0; i < len(bs)/2; i++ {
		bs[i] = bs[i] ^ bs[size-i-1]
		bs[size-i-1] = bs[i] ^ bs[size-i-1]
		bs[i] = bs[i] ^ bs[size-i-1]
	}
	fmt.Println(bs)
}

func TestBitTrimRight0(t *testing.T) {
	//a := 0
	//a := 255
	a := 256
	bs := intToBytesLE(int32(a))
	fmt.Println(bs)
	for len(bs) > 0 {
		if (bs[len(bs)-1] & 0xff) == 0 {
			bs = bs[:len(bs)-1]
		} else {
			break
		}
	}
	fmt.Println(bs)
	fmt.Println(hex.EncodeToString(bs))
}

func TestSortSlice(t *testing.T) {
	bs := []byte{3, 2, 1, 10}
	sort.Slice(bs, func(i, j int) bool {
		return i > j
	})
	fmt.Println(bs)
}

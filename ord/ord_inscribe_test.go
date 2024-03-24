package ord

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcdmempool "github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"hankmo.com/btcdemo/btcapi"
	"hankmo.com/btcdemo/btcapi/mempool"
	"hankmo.com/btcdemo/security"
)

func TestInscribeChild(t *testing.T) {
	// 创建api client
	net := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(net)

	// 读取被铭刻的图片文件
	workingDir, _ := os.Getwd()
	//file := "1.jpeg"
	//file := "2.jpg"
	file := "inscription.txt"
	filePath := fmt.Sprintf("%s/%s", workingDir, file)
	// if file size too max will return sendrawtransaction RPC _or: {"code":-26,"message":"tx-size"}
	fileContent, _ := os.ReadFile(filePath)
	// 读取文件 content type
	contentType := http.DetectContentType(fileContent)
	log.Printf("file contentType %s", contentType)

	// 私钥，后边铭刻需要用来签名
	utxoPrivateKeyHex := security.GetPrivateKey()
	// 接收铭文的地址
	destination := os.Getenv("addr")

	// 从私钥生成taproot地址
	utxoPrivateKeyBytes, _ := hex.DecodeString(utxoPrivateKeyHex)
	utxoPrivateKey, _ := btcec.PrivKeyFromBytes(utxoPrivateKeyBytes)
	utxoTaprootAddress, _ := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(utxoPrivateKey.PubKey())), net)

	// 查询地址的UTXO
	unspentList, _ := btcApiClient.ListUnspent(utxoTaprootAddress)

	// 从UTXO 中找到 output
	var parentInscriptionId = "3c430ee5f12393ff581a881613c3707f8f4197c47eb310ac64944bc4b362be15i0" // 父铭文id
	var commitFeeRate int64 = 2                                                                    // 预提交费率
	var revealFeeRate int64 = 2                                                                    // 最终铭刻的费率
	var commitTxOutPointList = make([]*wire.OutPoint, 0)                                           // 预提交花费的output
	var commitTxPrivateKeyList = make([]*btcec.PrivateKey, 0)                                      // 预提交时的私钥
	var ContentType = contentType                                                                  // 铭文的content type
	var Destination = destination                                                                  // 接收铭文的目标地址
	var client = btcApiClient                                                                      // rpc client
	var commitTxPrevOutputFetcher = txscript.NewMultiPrevOutFetcher(nil)                           // 预提交交易前一个 output 获取
	var revealTxPrevOutputFetcher = txscript.NewMultiPrevOutFetcher(nil)                           // 揭示交易前一个 output 获取
	var revealOutValue int64 = 1                                                                   // 铭文的 sat 值
	var Body = fileContent                                                                         // 铭文的内容

	for i := range unspentList {
		// 跳过铭文交易，铭文id中i之前的就是txid
		parentInscriptionTxHash := parentInscriptionId[0:strings.Index(parentInscriptionId, "i")]
		if unspentList[i].Outpoint.Hash.String() == parentInscriptionTxHash {
			continue
		}
		commitTxOutPointList = append(commitTxOutPointList, unspentList[i].Outpoint)
		commitTxPrivateKeyList = append(commitTxPrivateKeyList, utxoPrivateKey)
	}

	// 铭刻

	if len(commitTxPrivateKeyList) != len(commitTxOutPointList) {
		t.Fatal("the length of CommitTxPrivateKeyList and CommitTxOutPointList should be the same")
	}

	var err error
	var inscriptionScript []byte
	var commitTxAddressPkScript []byte
	// var recoveryPrivateKeyWIFString string

	privateKey, _ := btcec.NewPrivateKey()
	_, pidBytes, _ := ParseInscriptionHexId(parentInscriptionId)
	inscriptionBuilder := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(privateKey.PubKey())).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_FALSE).
		AddOp(txscript.OP_IF).
		AddData([]byte("ord")).
		// Two OP_DATA_1 should be OP_1. However, in the following link, it's not set as OP_1:
		// https://github.com/casey/ord/blob/0.5.1/src/inscription.rs#L17
		// Therefore, we use two OP_DATA_1 to maintain consistency with ord.
		AddOp(txscript.OP_DATA_1).
		AddOp(txscript.OP_DATA_1).
		AddData([]byte(ContentType)).
		AddOp(txscript.OP_DATA_3).
		AddOp(txscript.OP_DATA_3).
		AddData(pidBytes).
		AddOp(txscript.OP_0)
	//maxChunkSize := 520 // 脚本堆栈中每个元素的大小不能超过 520 个 bytes
	//bodySize := len(Body)
	//for i := 0; i < bodySize; i += maxChunkSize {
	//	end := i + maxChunkSize
	//	if end > bodySize {
	//		end = bodySize
	//	}
	//	to skip txscript.MaxScriptSize 10000
	//inscriptionBuilder.AddFullData(Body[i:end])
	//}
	inscriptionBuilder.AddData(Body)
	inscriptionBuilder.AddOp(txscript.OP_ENDIF)
	inscriptionScript, err = inscriptionBuilder.Script()
	// to skip txscript.MaxScriptSize 10000
	//scriptString, err := txscript.DisasmString(inscriptionScript) // 0 版本的脚本有效，1会失败？？
	throwErr(err)
	//fmt.Println("inscription script: ", scriptString)

	leafNode := txscript.NewBaseTapLeaf(inscriptionScript)
	proof := &txscript.TapscriptProof{
		TapLeaf:  leafNode,
		RootNode: leafNode,
	}

	controlBlock := proof.ToControlBlock(privateKey.PubKey())
	controlBlockWitness, err := controlBlock.ToBytes()
	throwErr(err)
	tapHash := proof.RootNode.TapHash()
	commitTxAddress, _ := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(privateKey.PubKey(), tapHash[:])), net)
	commitTxAddressPkScript, _ = txscript.PayToAddrScript(commitTxAddress)
	// recoveryPrivateKeyWIF, _ := btcutil.NewWIF(txscript.TweakTaprootPrivKey(*privateKey, tapHash[:]), net, true)
	// recoveryPrivateKeyWIFString = recoveryPrivateKeyWIF.String()

	// 构建 reveal 交易
	var revealTx = wire.NewMsgTx(wire.TxVersion)
	var revealTxPrevOutputValue int64
	var revealTxPrevOut *wire.TxOut

	// revealTx 第一个 input -- 父铭文
	parentInscriptionTxid := parentInscriptionId[:strings.Index(parentInscriptionId, "i")]
	hash, _ := chainhash.NewHashFromStr(parentInscriptionTxid)
	outp := &wire.OutPoint{Hash: *hash, Index: uint32(0)} // 父铭文的 outpoint
	parentInscriptionTxIn := wire.NewTxIn(outp, nil, nil)
	revealTx.AddTxIn(parentInscriptionTxIn)        // 父子铭文需要消费父铭文
	revealTx.TxIn[0].PreviousOutPoint = *outp      // 来源outputPoint
	revealTx.TxIn[0].Sequence = defaultSequenceNum // 来源outputPoint
	out, _ := getTxOutByOutPoint(client, outp)     // 父铭文的 output
	revealTxPrevOutputFetcher.AddPrevOut(revealTx.TxIn[0].PreviousOutPoint, out)
	revealTx.AddTxOut(wire.NewTxOut(out.Value, out.PkScript)) // 需要给父铭文持有者重发父铭文（因为UTXO被花费），所以 output 的 value 为父铭文的 value，公钥脚本为父铭文的公钥脚本
	// revealTx 的第二个 input -- commitTx
	// 预提交的 input 来源在 complete 的时候设置
	revalTxIn := wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, uint32(0)), nil, nil) // 完成时会将 outpoint 设置为 commitTx 的 hash
	revalTxIn.Sequence = defaultSequenceNum
	revealTx.AddTxIn(revalTxIn)
	receiver, _ := btcutil.DecodeAddress(Destination, net)
	scriptPubKey, _ := txscript.PayToAddrScript(receiver)
	revealTxOut := wire.NewTxOut(revealOutValue, scriptPubKey)
	revealTx.AddTxOut(revealTxOut)
	// 揭示交易前一个 ouput 就是预提交，其金额 = 揭示交易费 + 刻录铭文的sat
	revealTxPrevOutputValue = revealOutValue + int64(revealTx.SerializeSize())*revealFeeRate
	// TODO: 这里构建空签名，长度和算法没看懂？？
	emptySignature := make([]byte, 64)
	emptyControlBlockWitness := make([]byte, 33)
	revealTxFee := (int64(wire.TxWitness{emptySignature, inscriptionScript, emptyControlBlockWitness}.SerializeSize()+2+3) / 4) * revealFeeRate
	revealTxPrevOutputValue += revealTxFee
	revealTxPrevOut = &wire.TxOut{
		PkScript: commitTxAddressPkScript,
		Value:    revealTxPrevOutputValue,
	}

	// 构建 commit 交易

	var commitTx = wire.NewMsgTx(wire.TxVersion)

	// 发送给 commit 交易的总金额 = 交易费 + reveal 时铭文的 sat + reveal 时的交易费
	totalSenderAmount := btcutil.Amount(0)
	var changePkScript *[]byte
	// 将所有的 utxo 加入到 commit 交易的 input 中消费
	for i := range commitTxOutPointList {
		commitTxOut, _ := getTxOutByOutPoint(client, commitTxOutPointList[i])
		commitTxPrevOutputFetcher.AddPrevOut(*commitTxOutPointList[i], commitTxOut)
		if changePkScript == nil { // 将第一笔输入的 pkScript 作为 commit 交易的输出 pkScript，这样揭示交易中才能花费
			changePkScript = &commitTxOut.PkScript
		}
		commitTxIn := wire.NewTxIn(commitTxOutPointList[i], nil, nil) // 签名和witness暂时为 nil
		commitTxIn.Sequence = defaultSequenceNum
		commitTx.AddTxIn(commitTxIn)

		totalSenderAmount += btcutil.Amount(commitTxOut.Value)
	}
	// revealTxPrevOutput 在构建揭示交易是创建的，这里直接获取作为预提交的输出
	commitTx.AddTxOut(revealTxPrevOut)
	// 计算预提交交易费
	commitTxFee := btcutil.Amount(btcdmempool.GetTxVirtualSize(btcutil.NewTx(commitTx))) * btcutil.Amount(commitFeeRate)
	totalLeftAmount := totalSenderAmount - btcutil.Amount(revealTxPrevOutputValue) - commitTxFee // 余额
	if totalLeftAmount > 0 {
		// 找零输出: 再添加一个输出，其 pkScript 为与输入的一样，也就是 sender 后续可以消费这个输出
		commitTx.AddTxOut(wire.NewTxOut(int64(totalLeftAmount), *changePkScript))
	} else {
		if totalLeftAmount < 0 { // 余额不足，出错
			feeWithoutChange := btcutil.Amount(btcdmempool.GetTxVirtualSize(btcutil.NewTx(commitTx))) * btcutil.Amount(commitFeeRate)
			if totalSenderAmount-btcutil.Amount(revealTxPrevOutputValue)-feeWithoutChange < 0 {
				t.Fatal(errors.New("insufficient balance"))
			}
		}
	}

	// 签名 commitTx

	// commitTx input 有多个，每一个都需要签名
	for i := range commitTx.TxIn {
		txOut := commitTxPrevOutputFetcher.FetchPrevOutput(commitTx.TxIn[i].PreviousOutPoint)
		witness, _ := txscript.TaprootWitnessSignature(commitTx, txscript.NewTxSigHashes(commitTx, commitTxPrevOutputFetcher),
			i, txOut.Value, txOut.PkScript, txscript.SigHashDefault, commitTxPrivateKeyList[i])
		commitTx.TxIn[i].Witness = witness
	}

	// 填充 reveal 交易

	// 填充 commitTx 到 revealTx
	// 父铭文占了一个位置，所以 index 为 1
	revealTx.TxIn[1].PreviousOutPoint.Hash = commitTx.TxHash()
	revealTxPrevOutputFetcher.AddPrevOut(revealTx.TxIn[1].PreviousOutPoint, revealTxPrevOut)
	// revealTx 第一个输入为父铭文 input， index 为 0， 先签名
	txOut := revealTxPrevOutputFetcher.FetchPrevOutput(revealTx.TxIn[0].PreviousOutPoint)
	witness, err := txscript.TaprootWitnessSignature(revealTx, txscript.NewTxSigHashes(revealTx, revealTxPrevOutputFetcher),
		0, txOut.Value, txOut.PkScript, txscript.SigHashDefault, privateKey)
	throwErr(err)
	revealTx.TxIn[0].Witness = witness
	//revealTx 第二个输入为子铭文 input，index 为 1，签名
	// 揭示交易的前一个 output 为预提交交易
	witnessArray, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(revealTx, revealTxPrevOutputFetcher),
		txscript.SigHashDefault, revealTx, 0, revealTxPrevOutputFetcher, txscript.NewBaseTapLeaf(inscriptionScript))
	throwErr(err)
	//controlBlock := proof.ToControlBlock(privateKey.PubKey())
	//controlBlockWitness, err := controlBlock.ToBytes()
	throwErr(err)
	signature, err := schnorr.Sign(privateKey, witnessArray)
	throwErr(err)
	revealTx.TxIn[1].Witness = wire.TxWitness{signature.Serialize(), inscriptionScript, controlBlockWitness}

	//check tx max tx wight
	revealWeight := blockchain.GetTransactionWeight(btcutil.NewTx(revealTx))
	if revealWeight > MaxStandardTxWeight {
		t.Fatal(errors.New(fmt.Sprintf("reveal(index %d) transaction weight greater than %d (MAX_STANDARD_TX_WEIGHT): %d", 0, MaxStandardTxWeight, revealWeight)))
	}

	//for _, in := range revealTx.TxIn {
	//	for _, w := range in.Witness {
	//		fmt.Println(txscript.DisasmString(w))
	//	}
	//}

	// 提交交易

	var buf1 bytes.Buffer
	var buf2 bytes.Buffer
	var fees = int64(0)

	for _, in := range commitTx.TxIn {
		fees += commitTxPrevOutputFetcher.FetchPrevOutput(in.PreviousOutPoint).Value
	}
	for _, out := range commitTx.TxOut {
		fees -= out.Value
	}
	for _, in := range revealTx.TxIn {
		fees += revealTxPrevOutputFetcher.FetchPrevOutput(in.PreviousOutPoint).Value
	}
	for _, out := range revealTx.TxOut {
		fees -= out.Value
	}

	commitTx.Serialize(&buf1)
	revealTx.Serialize(&buf2)
	fmt.Println(hex.EncodeToString(buf1.Bytes()))
	fmt.Println(hex.EncodeToString(buf2.Bytes()))
	//return nil, nil, nil, 0, err

	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures | txscript.ScriptVerifyWitness
	eg, err := txscript.NewEngine(commitTx.TxOut[0].PkScript, commitTx, 0, flags, nil, nil, -1, commitTxPrevOutputFetcher)
	throwErr(err)
	err = eg.Execute()
	throwErr(err)

	eg, err = txscript.NewEngine(revealTx.TxOut[0].PkScript, revealTx, 1, flags, nil, nil, -1, revealTxPrevOutputFetcher)
	throwErr(err)
	err = eg.Execute()
	throwErr(err)

	fmt.Println("fees: ", fees)
	commitTxHash, err := client.BroadcastTx(commitTx)
	throwErr(err)
	fmt.Println("commitTxHash: " + commitTxHash.String())
	revealTxHash, err := client.BroadcastTx(revealTx)
	throwErr(err)
	fmt.Println("revealTxHash: " + revealTxHash.String())
	childInscription := fmt.Sprintf("%si0", revealTxHash)
	fmt.Println("childInscription: " + childInscription)
}

func throwErr(err error) {
	if err != nil {
		panic(err)
	}
}

func getTxOutByOutPoint(client btcapi.BTCAPIClient, outPoint *wire.OutPoint) (*wire.TxOut, error) {
	var txOut *wire.TxOut
	tx, err := client.GetRawTransaction(&outPoint.Hash)
	if err != nil {
		return nil, err
	}
	if int(outPoint.Index) >= len(tx.TxOut) {
		return nil, errors.New("err out point")
	}
	txOut = tx.TxOut[outPoint.Index]
	return txOut, nil
}

func ParseInscriptionHexId(id string) (string, []byte, error) {
	i := strings.Index(id, "i")
	txid := id[:i] // 铭文id i 前边为txid，i后为序号，从0开始
	// 序号处理为小端序的4个字节数组
	if num, err := strconv.ParseInt(id[i+1:], 10, 64); err != nil {
		return txid, []byte{}, err
	} else {
		bs, err := hex.DecodeString(txid)
		revertBytes(bs) // 比特币链的txid是字节反序
		trimedNumBytes := trimBytesRight0(intToBytesLE(int32(num)))
		return txid, append(bs, trimedNumBytes...), err
	}
}

func revertBytes(bs []byte) {
	size := len(bs)
	for i := 0; i < len(bs)/2; i++ {
		bs[i] = bs[i] ^ bs[size-i-1]
		bs[size-i-1] = bs[i] ^ bs[size-i-1]
		bs[i] = bs[i] ^ bs[size-i-1]
	}
}

func intToBytesLE(x int32) []byte {
	buf := bytes.NewBuffer([]byte{})
	if err := binary.Write(buf, binary.LittleEndian, x); err != nil {
		fmt.Printf("int to bytes failed: %v\n", err)
		return []byte{}
	}
	return buf.Bytes()
}

func trimBytesRight0(bs []byte) []byte {
	for len(bs) > 0 {
		// 如果最后一个字节为0，则去掉
		if (bs[len(bs)-1] & 0xff) == 0 {
			bs = bs[:len(bs)-1]
		} else {
			break
		}
	}
	return bs
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

func Test1(t *testing.T) {
	// 12841 21547 30253 32767 32767 ...
	//ss := "3229,542b,762d,982f,ba31,dc33,fe35,2038,423a,643c"
	//ss := "2932,2b54"
	ss := "2710,2904"
	for i, s := range strings.Split(ss, ",") {
		bs, err := hex.DecodeString(s)
		if err != nil {
			fmt.Println(err)
		}
		x := binary.BigEndian.Uint16(bs)
		fmt.Println(i, " -> ", x)
	}
}

func Test2(t *testing.T) {
	s := "7b202270223a202267656e2d6272632d373231222c20226f70223a20226d696e74222c202273223a20226f726469626f7473222c2022745f696e73223a205b202262373230356434306633623162313438363536376630643665353366663238313239383364623463303361643764333630363831326364313530633634383032693022205d2c202268223a202261613064333362373438653031373735323861393130613536613631633437626565326261396236393734393232386436353230303439633066656133663466222c20226964223a2022353534222c202261223a205b205b20302c2022626974636f696e2d6f72616e676522205d2c205b20302c20227261696e626f7722205d2c205b20302c2022626c61636b2d616e642d77686974652d747269616e67756c617222205d2c205b20302c202273717561726522205d2c205b20302c2022686170707922205d205d207d"
	fmt.Println(string(parseHex(s)))
	fmt.Println(string(parseHex("746578742f706c61696e3b636861727365743d7574662d38")))
	fmt.Println(string(parseHex("746578742f6a617661736372697074")))
	fmt.Println(string(parseHex("6c657420636f6e666967203d207b0a2020696d616765536d6f6f7468696e673a20747275652c0a202073697a653a207b0a2020202077696474683a20313030302c0a202020206865696768743a20313030300a20207d2c0a20206d657461646174613a2022663031376136316264393631356663333730653030303039613732396337336231393733333238393864373436613338333631373562663339653735656536376930222c0a202066616c6c6261636b496d6167653a2022663363643363343865323962636464656166343930616231613138396531306633623738313361643731643766623535363235336464646432616365376563336930222c0a20206b65793a2022343566333961653233656433303362306533613266623138393434666637303162356239343864316363333733313565336261643634316430326561366431396930220a7d0a0a6c657420736372697074203d20646f63756d656e742e63757272656e745363726970740a646f63756d656e742e686561642e617070656e644368696c6428646f63756d656e742e637265617465456c656d656e7428277363726970742729292e696e6e657248544d4c3d22696d706f727428272f636f6e74656e742f373639316161643062353632336235303766623366646130313563373939336534663335333666633562356365616132366535376239396637623430633431316930272922")))
}

func parseHex(s string) []byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bs
}

func TestParseHex(t *testing.T) {
	b := parseHex("746578742f706c61696e3b20636861727365743d7574662d38")
	fmt.Println(string(b))
}

func TestParseScript(t *testing.T) {
	bs, err := hex.DecodeString("58ca6775286739c269ec2a0c4e6a0d7726e05fd583a507ed73a1f64b875d4c509947f055a8bfef4dfd264b294f529f5383079bb33bfd8cc98e56f7e3636f209c")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(txscript.DisasmString(bs))
	bs, _ = hex.DecodeString("b816493450cf8dc9365035b0e66ababda423ff5a8960ba4fc6166c8b3fc94a2c49df539c8ac3e76e4c55a168f963cf98effe522f73ac49aca6e54f26ebdf56d2")
	fmt.Println(txscript.DisasmString(bs))
	bs, _ = hex.DecodeString("62fa03a5a095150a197bf17fdafe89ddd4a8e92b277dff9a703e9a5a5056ed2ba366e2de212b1c26b3c6e5521f754c3885ac5ceaaccae8b5f492d0ca039d2449")
	fmt.Println(txscript.DisasmString(bs))
	bs, _ = hex.DecodeString("201f8bb8197e15508c8a7490a0c520a5831f52f87b7ac800c064688594f001ce47ac0063036f7264010119746578742f706c61696e3b20636861727365743d7574662d38032011ba05171bb6c91c19b89b4912a973eaaed6b02984d10c0c8dfbadf49f090239000568656c6c6f68")
	fmt.Println(txscript.DisasmString(bs))
	bs, _ = hex.DecodeString("c11f8bb8197e15508c8a7490a0c520a5831f52f87b7ac800c064688594f001ce47")
	fmt.Println(txscript.DisasmString(bs))
}

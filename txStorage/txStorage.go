package txStorage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"kortho/api"
	pb "kortho/api/message"
	"kortho/blockchain"
	"kortho/transaction"
	"kortho/types"
	"log"
	"net/rpc"
	"os"
	"strings"
	"time"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
)

type TxStorage struct {
	currentHeght uint64
	db           *sql.DB
	blockDB      *blockchain.Blockchain
	conn         *grpc.ClientConn
}

//ReqBlockrpc requests blocks from height 'LowH' to 'HeiH'.
type ReqBlockrpc struct {
	GetLeader    bool
	Addr         string //request address
	ReqMaxHeight bool   //request leader max block height
	ReqBlocks    bool   //request leader blocks from height 'LowH' to 'HeiH'
	LowH         uint64 //form LowH
	HeiH         uint64 //to HeiH
}

//ReSBlockrpc result info
type ReSBlockrpc struct {
	Data       []byte //blocks data
	LeaderAddr string
	MaxHieght  uint64 //leader max block height
}

type Order struct {
	Id         string `json:"id"`
	Address    string `json:"address"`
	Price      uint64 `json:"price"`
	Hash       string `json:"hash"`
	Signature  string `json:"signature"`
	Ciphertext string `json:"ciphertext"`
	Tradename  string `json:"tradename"`
	Region     string `json:"region"`
}

type Transaction struct {
	Nonce       uint64 `json:"nonce"`
	BlockNumber uint64 `json:"blocknumber"`
	Amount      uint64 `json:"amount"`
	From        string `json:"from"`
	To          string `json:"to"`
	Hash        string `json:"hash"`
	Signature   string `json:"signature"`
	Time        int64  `json:"time"`
	Script      string `json:"script"`
	Ord         Order  `json:"ord"`
	KtoNum      uint64 `json:"ktonum"`
	PckNum      uint64 `json:"pcknum"`
	Tag         int32  `json:"tag"`
	Fee         uint64 `json:"fee,omitempty"`
}

const (
	K_ASCII         = 75
	SQLERR_1062     = "PRIMARY"
	SELECTMAXHEIGHT = "select max_height from max_height where id=?" //table max_height stores the max height.
	INSERTMAXHEIGHT = "INSERT INTO max_height (id,max_height) VALUES (?,?)"
	UPDATEMAXHEIGHT = "update max_height set max_height=? where id=?"
	INSERTTXDATA    = "INSERT INTO txdata (tx_height,tx_hash,tx_from,tx_to,tx_data) values(?,?,?,?,?)" //table txdata stores every tx data.

	TargetAddr = "106.12.73.41:12346"
)

var Max_Height uint64

func (ts *TxStorage) Run(db *sql.DB) {
	ts.db = db
	defer ts.db.Close()
	currentH, err := ts.getMaxHeightFromTable()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Println("get max height:", currentH)
	ts.currentHeght = currentH
	ts.blockDB = blockchain.New()

	// maxH, err := ts.blockDB.GetMaxBlockHeight()
	// if err != nil {
	// 	log.Println(err)
	// 	os.Exit(1)
	// }

	// Max_Height = maxH

	err = ts.getConnection()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer ts.conn.Close()

	for {
		time.Sleep(time.Millisecond * 500)

		// if ts.currentHeght > Max_Height {
		// 	err = ts.saveOnlineTxsDataToDB(ts.currentHeght)
		// } else {
		// 	err = ts.saveLocalDBTxsDataToDB(ts.currentHeght)
		// }
		err := ts.saveOnlineTxsDataToDB(ts.currentHeght)
		if err != nil {
			log.Println(err)
			continue
		}

		err = ts.updateMaxHeight()
		if err != nil {
			log.Printf("updateMaxHeight error: %v\n", err)
		}
		ts.currentHeght++
	}
}

func AddressToByte(a types.Address) []byte {
	var b []byte
	b = a[:]
	return b
}

func (ts *TxStorage) getBlockbyHeight(height uint64) ([]byte, error) {
	conn, err := rpc.DialHTTP("tcp", TargetAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := ReqBlockrpc{
		ReqBlocks: true,
		LowH:      height,
	}
	res := ReSBlockrpc{}
	err = conn.Call("RequestManage.HandleGetBlockByHeight", req, &res)
	if err != nil {
		return nil, fmt.Errorf("Call HandleGetBlockByHeight error:%v", err)
	}

	return res.Data, nil
}

func (ts *TxStorage) saveLocalDBTxsDataToDB(height uint64) error {
	b, err := ts.blockDB.GetBlockByHeight(height)
	if err != nil {
		return err
	}

	for _, tx := range b.Transactions {
		if checkAddr(tx.From.String()) {

			var tmpTx Transaction
			tmpTx.Hash = hex.EncodeToString(tx.Hash)
			tmpTx.From = string(AddressToByte(tx.From))
			tmpTx.Amount = tx.Amount
			tmpTx.Nonce = tx.Nonce
			tmpTx.To = string(AddressToByte(tx.To))
			tmpTx.Signature = hex.EncodeToString(tx.Signature)
			tmpTx.Time = tx.Time
			tmpTx.BlockNumber = tx.BlockNumber
			tmpTx.Script = tx.Script
			tmpTx.KtoNum = tx.KtoNum
			tmpTx.PckNum = tx.PckNum
			tmpTx.Tag = tx.Tag
			tmpTx.Fee = tx.Fee

			if tx.Order != nil {
				tmpTx.Ord.Id = string(tx.Order.ID)
				tmpTx.Ord.Hash = hex.EncodeToString(tx.Order.Hash)
				tmpTx.Ord.Signature = hex.EncodeToString(tx.Order.Signature)
				tmpTx.Ord.Ciphertext = hex.EncodeToString(tx.Order.Ciphertext)
				tmpTx.Ord.Address = string(AddressToByte(tx.Order.Address))
				tmpTx.Ord.Price = tx.Order.Price
			}

			txData, err := json.Marshal(&tmpTx)
			if err != nil {
				return err
			}

			res, err := ts.db.Exec(INSERTTXDATA, tmpTx.BlockNumber, tmpTx.Hash, tmpTx.From, tmpTx.To, string(txData))
			if err != nil {
				if contain := strings.Contains(err.Error(), SQLERR_1062); contain {
					log.Println(err)
					continue
				}
				return err
			}
			printInfo := "Stored txdata:{\nblock_height = %v\ntx_hash = %v\ntx_from = %v\ntx_to = %v\ntx_data len = %v,from addr len = %v,to addr len = %v}\n"
			log.Printf(printInfo, tmpTx.BlockNumber, tmpTx.Hash, tmpTx.From, tmpTx.To, len(string(txData)), len(tmpTx.From), len(tmpTx.To))
			if res != nil {
				ra, _ := res.RowsAffected()
				log.Printf("RowsAffected: %v.\n\n", ra)
			}
		}
	}
	return nil
}

func checkAddr(address string) bool {
	addr := address
	if len(addr) > 0 {
		ad := []rune(addr)
		if ad[0] == K_ASCII {
			return true
		}
	}
	return false
}

func (ts *TxStorage) getMaxHeightFromTable() (uint64, error) {
	rows, err := ts.db.Query(SELECTMAXHEIGHT, 1)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var currentH uint64
	if rows.Next() {
		rows.Scan(&currentH)
	}
	if rows.Err() != nil {
		return 0, rows.Err()
	}

	if currentH == 0 {
		_, err := ts.db.Exec(INSERTMAXHEIGHT, 1, 1)
		if err != nil {
			return 0, err
		}
		currentH++
		return currentH, nil
	}

	return currentH, nil
}

func (ts *TxStorage) updateMaxHeight() error {
	_, err := ts.db.Exec(UPDATEMAXHEIGHT, ts.currentHeght, 1)
	if err != nil {
		return err
	}
	return nil
}

func (ts *TxStorage) getConnection() error {
	conn, err := grpc.Dial(TargetAddr, grpc.WithInsecure())
	if err != nil {
		return err
	}
	ts.conn = conn
	return nil
}

func (ts *TxStorage) getTransactions(height uint64) ([]*transaction.Transaction, error) {
	cc := pb.NewGreeterClient(ts.conn)

	resN, err := cc.GetMaxBlockNumber(context.Background(), &pb.ReqMaxBlockNumber{})
	if err != nil {
		return nil, err
	}

	if height > resN.MaxNumber {
		return nil, fmt.Errorf("OverDBMaxHeight:request height[%v]  database max height[%v]", height, resN.MaxNumber)
	}

	resB, err := cc.GetBlockByNum(context.Background(), &pb.ReqBlockByNumber{Height: height})
	if err != nil {
		return nil, err
	}

	var Tx []*transaction.Transaction
	if len(resB.Txs) > 0 {
		for _, msTx := range resB.Txs {
			if msTx != nil {
				t, err := api.MsgTxToTx(msTx)
				if err != nil {
					return nil, err
				}
				Tx = append(Tx, t)
			}
		}
	}
	return Tx, nil
}

func (ts *TxStorage) saveOnlineTxsDataToDB(height uint64) error {
	txs, err := ts.getTransactions(height)
	if err != nil {
		return err
	}

	for _, tx := range txs {
		if checkAddr(tx.From.String()) {
			var tmpTx Transaction
			tmpTx.Hash = hex.EncodeToString(tx.Hash)
			tmpTx.From = string(AddressToByte(tx.From))
			tmpTx.Amount = tx.Amount
			tmpTx.Nonce = tx.Nonce
			tmpTx.To = string(AddressToByte(tx.To))
			tmpTx.Signature = hex.EncodeToString(tx.Signature)
			tmpTx.Time = tx.Time
			tmpTx.BlockNumber = tx.BlockNumber
			tmpTx.Script = tx.Script
			tmpTx.KtoNum = tx.KtoNum
			tmpTx.PckNum = tx.PckNum
			tmpTx.Tag = tx.Tag
			if tx.Order != nil {
				tmpTx.Ord.Id = string(tx.Order.ID)
				tmpTx.Ord.Hash = hex.EncodeToString(tx.Order.Hash)
				tmpTx.Ord.Signature = hex.EncodeToString(tx.Order.Signature)
				tmpTx.Ord.Ciphertext = hex.EncodeToString(tx.Order.Ciphertext)
				tmpTx.Ord.Address = string(AddressToByte(tx.Order.Address))
				tmpTx.Ord.Price = tx.Order.Price
			}

			txData, err := json.Marshal(&tmpTx)
			if err != nil {
				return err
			}

			res, err := ts.db.Exec(INSERTTXDATA, tmpTx.BlockNumber, tmpTx.Hash, tmpTx.From, tmpTx.To, string(txData))
			if err != nil {
				if contain := strings.Contains(err.Error(), SQLERR_1062); contain {
					log.Println(err)
					continue
				}
				return err
			}
			printInfo := "Stored txdata:{\nblock_height = %v\ntx_hash = %v\ntx_from = %v\ntx_to = %v\ntx_data len = %v,from addr len = %v,to addr len = %v}\n"
			log.Printf(printInfo, tmpTx.BlockNumber, tmpTx.Hash, tmpTx.From, tmpTx.To, len(string(txData)), len(tmpTx.From), len(tmpTx.To))
			if res != nil {
				ra, _ := res.RowsAffected()
				log.Printf("RowsAffected: %v.\n\n", ra)
			}
		}
	}
	return nil
}

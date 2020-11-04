package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"kortho/types"
	"log"
	"os"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"

	_ "github.com/go-sql-driver/mysql"
)

var ErrorMap = map[int]string{
	0:      "ok",
	-41201: "Json解析失败",
	-41202: "sql查询失败",
	-41203: "没有此交易",
	-41204: "此hash没有交易",
	-41205: "数据错误",
	-41206: "没有块数据",
	-41207: "交易失败",
	-41208: "获取块高失败",
}

var (
	Success          = 0
	ErrJSON          = -41201
	ErrQuery         = -41202
	ErrNoTransaction = -41203
	ErrNoTxByHash    = -41204
	ErrData          = -41205
	ErrNoBlock       = -41206
	ErrtTx           = -41207
	ErrNoBlockHeight = -41208
)

type TxOrder struct {
	Id         string `json:"id"`
	Address    string `json:"address"`
	Price      uint64 `json:"price"`
	Hash       string `json:"hash"`
	Signature  string `json:"signature"`
	Ciphertext string `json:"ciphertext"`
	Tradename  string `json:"tradename"`
	Region     string `json:"region"`
}
type TxTransaction struct {
	Nonce       uint64  `json:"nonce"`
	BlockNumber uint64  `json:"blocknumber"`
	Amount      uint64  `json:"amount"`
	From        string  `json:"from"`
	To          string  `json:"to"`
	Hash        string  `json:"hash"`
	Signature   string  `json:"signature"`
	Time        int64   `json:"time"`
	Script      string  `json:"script"`
	Ord         TxOrder `json:"ord"`
	KtoNum      uint64  `json:"ktonum"`
	PckNum      uint64  `json:"pcknum"`
	Tag         int32   `json:"tag"`
	Fee         uint64  `json:"fee"`
}

const (
	QUERYBYADDR      = "SELECT tx_data FROM txdata WHERE tx_from=? OR tx_to=? ORDER BY tx_height DESC LIMIT ?,?"
	QUERYBYADDRTOTAL = "SELECT count(1) FROM txdata WHERE tx_from=? OR tx_to=?"
	QUERYBYHASH      = "SELECT tx_data FROM txdata WHERE tx_hash=?"
	dsn              = "root:123456@tcp(localhost:3306)/addr_txdata?charset=utf8"
)

type Server struct {
	r  *fasthttprouter.Router
	db *sql.DB
}

type reqBody struct {
	Limit   uint64 `json:"limit"`
	Page    uint64 `json:"page"`
	Address string `json:"address"`
	Hash    string `json:"hash"`
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Failed to connect database:", err)
		os.Exit(1)
	}
	s := &Server{r: fasthttprouter.New(), db: db}
	s.Run()
}

func AddressToByte(a types.Address) []byte {
	var b []byte
	b = a[:]
	return b
}

func (s *Server) Run() {
	s.r.POST("/GetTxsByAddr", s.GetTxsByAddr)
	s.r.POST("/GetTxsByHash", s.GetTxsByHash)
	log.Println("Run Server for web to get txdata...")
	err := fasthttp.ListenAndServe("0.0.0.0:6868", s.r.Handler)
	if err != nil {
		log.Println("start fasthttp fail:", err.Error())
		os.Exit(1)
	}
}

func (s *Server) GetTxsByAddr(ctx *fasthttp.RequestCtx) {
	var reqData reqBody
	var resBody []byte
	var errorCode int
	defer func() {
		if errorCode != Success {
			resStr := fmt.Sprintf(`{"errorcode":%d,"errormsg":"%s"}`, errorCode, ErrorMap[errorCode])
			resBody = []byte(resStr)
		}
		ctx.Write(resBody)
	}()
	ctx.Request.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Request.Header.Add("Access-Control-Allow-Headers", "Content-Type")
	ctx.Request.Header.Set("content-type", "application/json")

	reqB := ctx.PostBody()
	log.Println("request body:", string(reqB))
	if err := json.Unmarshal(reqB, &reqData); err != nil {
		errorCode = ErrJSON
		log.Printf("json Unmarshal error:%v\n", err)
		return
	}
	if reqData.Limit == 0 {
		reqData.Limit = 10
	}
	log.Println("Query:", reqData.Address, reqData.Limit, reqData.Page)
	rel := s.db.QueryRow(QUERYBYADDRTOTAL, reqData.Address, reqData.Address)
	var total int
	rel.Scan(&total)

	rows, err := s.db.Query(QUERYBYADDR, reqData.Address, reqData.Address, reqData.Page, reqData.Limit)
	if err != nil {
		errorCode = ErrQuery
		log.Printf("sql query error:%v\n", err)
		return
	}
	defer rows.Close()

	var Tx []TxTransaction
	for rows.Next() {
		var txData string
		rows.Scan(&txData)
		var tx TxTransaction
		err := json.Unmarshal([]byte(txData), &tx)
		if err != nil {
			errorCode = ErrJSON
			log.Printf("json Unmarshal error:%v\n", err)
			return
		}
		Tx = append(Tx, tx)
	}

	var respData struct {
		ErrorCode       int             `json:"errorcode"`
		ErrorMsg        string          `json:"errormsg"`
		Total           int             `json:"total"`
		TransactionList []TxTransaction `json:"transactionlist"`
	}
	errorCode = Success
	respData.ErrorCode = errorCode
	respData.Total = total
	respData.ErrorMsg = ErrorMap[errorCode]
	respData.TransactionList = Tx

	resBody, err = json.Marshal(respData)
	if err != nil {
		errorCode = ErrJSON
		log.Printf("json Marshal error:%v\n", err)
		return
	}
	log.Printf("Finished GetTxsByAddr address=%v,total=%v,page=%v,limit=%v", reqData.Address, total, reqData.Page, reqData.Limit)
	return
}

func (s *Server) GetTxsByHash(ctx *fasthttp.RequestCtx) {
	var reqData reqBody
	var resBody []byte
	var errorCode int
	defer func() {
		if errorCode != Success {
			resStr := fmt.Sprintf(`{"errorcode":%d,"errormsg":"%s"}`, errorCode, ErrorMap[errorCode])
			resBody = []byte(resStr)
		}
		ctx.Write(resBody)
	}()
	ctx.Request.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Request.Header.Add("Access-Control-Allow-Headers", "Content-Type")
	ctx.Request.Header.Set("content-type", "application/json")

	reqB := ctx.PostBody()
	if err := json.Unmarshal(reqB, &reqData); err != nil {
		errorCode = ErrJSON
		log.Printf("json Unmarshal error:%v\n", err)
		return
	}
	rows, err := s.db.Query(QUERYBYHASH, reqData.Hash)
	if err != nil {
		errorCode = ErrQuery
		log.Printf("sql query error:%v\n", err)
		return
	}
	defer rows.Close()

	var tx TxTransaction
	for rows.Next() {
		var txData string
		rows.Scan(&txData)
		err := json.Unmarshal([]byte(txData), &tx)
		if err != nil {
			errorCode = ErrJSON
			log.Printf("json Unmarshal error:%v\n", err)
			return
		}
	}

	var respData struct {
		ErrorCode       int           `json:"errorcode"`
		ErrorMsg        string        `json:"errormsg"`
		TransactionList TxTransaction `json:"transaction"`
	}
	errorCode = Success
	respData.ErrorCode = errorCode
	respData.ErrorMsg = ErrorMap[errorCode]
	respData.TransactionList = tx

	resBody, err = json.Marshal(respData)
	if err != nil {
		errorCode = ErrJSON
		log.Printf("json Marshal error:%v\n", err)
		return
	}
	log.Println("Finished GetTxsByHash hash=", reqData.Hash)
	return
}

package main

import (
	"context"
	"contractServer/message"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/astaxie/beego/utils"
	"github.com/buaazp/fasthttprouter"
	"github.com/dgraph-io/badger"
	"github.com/valyala/fasthttp"
	"google.golang.org/grpc"
)

const (
	SuccessCode      = 0
	WrongPassword    = 1
	UserNotExist     = 2
	RegisterError    = 3
	LoadError        = 4
	UsedEmail        = 5
	WrongEmail       = 6
	SendEmailErr     = 7
	CreatContractErr = 8
)

type Server struct {
	addr string
	fasthttprouter.Router
	db *badger.DB
}

type emailInfo struct {
	username string
	password string
	host     string
	port     uint32
}

type resultInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	//Data    interface{} `json:"data"`
}

const (
	usersInfo  = "userInfo"
	emailaddr  = "email"
	tkenName   = "tokenName"
	symbols    = "symbol"
	notExist   = "NotExist"
	registerOk = "RegisterOk"
)

const leaderaddr = "106.12.186.120:8545"

var sendcode string
var sendEmailAddr string

func verifyEmailFormat(email string) bool {
	pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*` //匹配电子邮箱
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

func verifyPassword(s string) bool {
	var hasNumber, hasUpperCase, hasLowercase, checkLength bool
	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsUpper(c):
			hasUpperCase = true
		case unicode.IsLower(c):
			hasLowercase = true
		case c == '#' || c == '|':
			return false
			// case unicode.IsPunct(c) || unicode.IsSymbol(c):
			// 	hasSpecial = true
		}
	}
	if len(s) >= 6 {
		checkLength = true
	}
	return hasNumber && checkLength && hasUpperCase || hasLowercase //&& hasSpecial
}

func checkUserInfo(email, password []byte) int {
	if len(email) <= 0 {
		return WrongEmail
	}
	if !verifyEmailFormat(string(email)) {
		return WrongEmail
	}

	if len(password) <= 0 {
		return WrongPassword
	}
	if !verifyPassword(string(password)) {
		return WrongPassword
	}
	return SuccessCode
}

func set(tx *badger.Txn, k, v []byte) error {
	return tx.Set(k, v)
}

func get(tx *badger.Txn, k []byte) ([]byte, error) {
	it, err := tx.Get(k)
	if err == badger.ErrKeyNotFound {
		err = fmt.Errorf(notExist)
	}
	if err != nil {
		return nil, err
	}
	return it.ValueCopy(nil)
}

func (s *Server) mset(m, k, v []byte) error {
	tx := s.db.NewTransaction(true)
	defer tx.Discard()
	if err := set(tx, eMapKey(m, k), v); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) mget(m, k []byte) ([]byte, error) {
	tx := s.db.NewTransaction(true)
	defer tx.Discard()

	return get(tx, eMapKey(m, k))
}

// 'm' + mlen + m + '+' + k
func eMapKey(m, k []byte) []byte {
	buf := []byte{}
	buf = append([]byte{'m'}, E32func(uint32(len(m)))...)
	buf = append(buf, m...)
	buf = append(buf, byte('+'))
	buf = append(buf, k...)
	return buf
}

func E32func(a uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, a)
	return buf
}

func (s *Server) Register(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Content-Type", "application/json")

	var result resultInfo
	defer func() {
		jsbyte, _ := json.Marshal(result)
		ctx.Write(jsbyte)
	}()

	args := ctx.QueryArgs()
	email := args.Peek("email")
	password := args.Peek("password")
	verifycode := args.Peek("verifycode")

	if sendEmailAddr != string(email) {
		log.Printf("email address not matched:first time[%s],second time[%s]\n", sendEmailAddr, string(email))
		result.Code = WrongEmail
		result.Message = fmt.Errorf("email address not matched:first time[%s],second time[%s]", sendEmailAddr, string(email)).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	if sendcode != string(verifycode) {
		log.Printf("verify code not matched:sendcode[%s],inputcode[%s]\n", sendcode, verifycode)
		result.Code = RegisterError
		result.Message = fmt.Errorf("verify code not matched:sendcode[%s],inputcode[%s]", sendcode, verifycode).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	statusCode := checkUserInfo(email, password)
	if statusCode != 0 {
		log.Printf("Register checkUserInfo: Wrong email or password.\n")
		result.Code = statusCode
		result.Message = "Wrong email or password"
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	// tx := s.db.NewTransaction(true)
	// defer tx.Discard()
	// if err := set(tx, email, password); err != nil {
	// 	log.Printf("Register new user error:%v\n", err)
	// 	result.Code = RegisterError
	// 	result.Message = err.Error()
	// 	ctx.Response.SetStatusCode(http.StatusBadRequest)
	// 	return
	// }
	// tx.Commit()

	//set email -> password
	if err := s.mset([]byte(usersInfo), email, password); err != nil {
		log.Printf("Set map '[email]password' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	//set email -> email
	if err := s.mset([]byte(emailaddr), email, email); err != nil {
		log.Printf("Set map '[email]email' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	result.Code = SuccessCode
	result.Message = registerOk
	ctx.Response.SetStatusCode(http.StatusOK)
	sendEmailAddr = ""
	sendcode = ""
	log.Printf("Register Ok!\n")
	return
}

func (s *Server) SendEmail(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Content-Type", "application/json")
	var result resultInfo
	defer func() {
		jsbyte, _ := json.Marshal(result)
		ctx.Write(jsbyte)
	}()

	args := ctx.QueryArgs()
	email := args.Peek("email")

	//Alrady registered email can not be registered.
	value, err := s.mget([]byte(emailaddr), email)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("Register error:%v,email:%v\n", err, string(value))
			result.Code = RegisterError
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusBadRequest)
			return
		}
	}
	if len(value) > 0 {
		log.Printf("Register error:The email addrss[%v] already in use.\n", string(email))
		result.Code = UsedEmail
		result.Message = fmt.Errorf("The email addrss[%v] already in use", string(email)).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	//send email
	sendcode = genValidateCode(6) //随机生成6位验证码
	if err := s.sendEmail(string(email), sendcode); err != nil {
		log.Printf("Register send email error:%v.\n", err)
		result.Code = SendEmailErr
		result.Message = fmt.Errorf("Send email error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	result.Code = SuccessCode
	result.Message = "SendEmailOk"
	ctx.Response.SetStatusCode(http.StatusOK)
	sendEmailAddr = string(email)
	log.Printf("Send Email Ok!\n")
	return
}

func (s *Server) Login(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Content-Type", "application/json")

	var result resultInfo
	defer func() {
		jsbyte, _ := json.Marshal(result)
		ctx.Write(jsbyte)
	}()

	args := ctx.QueryArgs()
	email := args.Peek("email")
	password := args.Peek("password")

	// statusCode := checkUserInfo(email, password)
	// if statusCode != 0 {
	// 	log.Printf("Login checkUserInfo: error code %v.\n", statusCode)
	// 	result.Code = statusCode
	// 	result.Message = "WrongParameters"
	// 	ctx.Response.SetStatusCode(http.StatusBadRequest)
	// 	return
	// }

	// tx := s.db.NewTransaction(true)
	// defer tx.Discard()
	// value, err := get(tx, email)

	value, err := s.mget([]byte(usersInfo), email)
	if err != nil {
		log.Printf("Login error:%v\n", err)
		if err.Error() == notExist {
			result.Code = UserNotExist
		} else {
			result.Code = LoadError
		}
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	if string(password) != string(value) {
		log.Printf("Login error: wrong password!\n")
		result.Code = WrongPassword
		result.Message = "WrongPassword"
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	result.Code = SuccessCode
	result.Message = "LoadOk"
	ctx.Response.SetStatusCode(http.StatusOK)
	log.Printf("Login Ok!\n")
	return

}

func (s *Server) CreatContract(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Content-Type", "application/json")

	var result resultInfo
	defer func() {
		jsbyte, _ := json.Marshal(result)
		ctx.Write(jsbyte)
	}()

	args := ctx.QueryArgs()
	address := args.Peek("address")
	priv := args.Peek("private")
	tokenName := args.Peek("tokenName") //need be keeped into db
	symbol := args.Peek("symbol")       //need be keeped into db
	total := args.Peek("total")

	// Existing tokenName can not be created.
	tvalue, err := s.mget([]byte(tkenName), tokenName)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("CreatContract error:%v,tokenName:%v\n", err, string(tokenName))
			result.Code = CreatContractErr
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusBadRequest)
			return
		}
	}
	if len(tvalue) > 0 {
		log.Printf("CreatContract error:The tokenName[%v] already Existing.\n", string(tokenName))
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("The tokenName[%v] already Existing", string(tokenName)).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	// Existing Symbol can not be created.
	svalue, err := s.mget([]byte(symbols), symbol)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("CreatContract error:%v,symbol:%v\n", err, string(symbol))
			result.Code = CreatContractErr
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusBadRequest)
			return
		}
	}
	if len(svalue) > 0 {
		log.Printf("CreatContract error:The symbol[%v] already Existing.\n", string(symbol))
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("The symbol[%v] already Existing", string(symbol)).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	conn, err := grpc.Dial(leaderaddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Printf("grpc Dial error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("grpc Dial error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	client := message.NewGreeterClient(conn)
	cx := context.Background()

	bl, err := client.GetBalance(cx, &message.ReqBalance{Address: string(address)})
	if err != nil {
		log.Printf("GetBalance error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract client.GetBalance error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	if bl.Balnce < uint64(500001) {
		log.Printf("Error: bl.Balnce < uint64(500001) error")
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract error: bl.Balnce < uint64(500001) error").Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	res, err := client.GetAddressNonceAt(cx, &message.ReqNonce{Address: string(address)})
	if err != nil {
		log.Printf("GetAddressNonceAt error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract GetAddressNonceAt error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	t, err := strconv.ParseInt(string(total), 10, 64)
	if err != nil {
		log.Printf("strconv.ParseInt error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract strconv.ParseInt error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	_, err = client.CreateContract(cx, &message.ReqTokenCreate{
		From: string(address), To: "KtoCBhhMUrmcD5G5dmjLQJCiPeJLMfCt8EJE2ordaPc5B7d",
		Amount: uint64(500001), Nonce: res.Nonce,
		Fee: uint64(500001), Total: uint64(t),
		Priv: string(priv), Symbol: string(symbol),
	})
	if err != nil {
		log.Printf("CreatContract error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	tct, err := client.MintToken(cx, &message.ReqTokenCreate{
		From: string(address), To: "KtoCBhhMUrmcD5G5dmjLQJCiPeJLMfCt8EJE2ordaPc5B7d",
		Amount: uint64(500001), Nonce: res.Nonce + 1,
		Fee: uint64(500001), Total: uint64(t),
		Priv: string(priv), Symbol: string(symbol),
	})
	if err != nil {
		log.Printf("MintToken error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("MintToken error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	//set tokenName -> tokenName
	if err := s.mset([]byte(tkenName), tokenName, tokenName); err != nil {
		log.Printf("Set map '[tokenName]tokenName' error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	//set symbol -> symbol
	if err := s.mset([]byte(symbols), symbol, symbol); err != nil {
		log.Printf("Set map '[symbol]symbol' error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	result.Code = SuccessCode
	result.Message = fmt.Errorf("CreatContract successfully,hash:%v", tct.Hash).Error()
	ctx.Response.SetStatusCode(http.StatusOK)
	log.Printf("CreatContract Ok!\n")
	return
}

func (s *Server) sendEmail(toEmail string, code string) error {
	config := `{"username":"kortho@yeah.net","password":"MYVELWIDTMAQFVEH","host":"smtp.yeah.net","port":25}`
	emailReg := utils.NewEMail(config)
	//内容配置
	emailReg.Subject = "账户注册邮箱验证"
	emailReg.From = "kortho@yeah.net"
	emailReg.To = []string{toEmail}
	//发送给用户激活地址
	emailReg.Text = code
	//发送
	err := emailReg.Send()
	if err != nil {
		fmt.Println("send email error: ", err)
		return err
	}
	return nil
}

func genValidateCode(width int) string {
	numeric := [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	r := len(numeric)
	rand.Seed(time.Now().UnixNano())

	var sb strings.Builder
	for i := 0; i < width; i++ {
		fmt.Fprintf(&sb, "%d", numeric[rand.Intn(r)])
	}
	return sb.String()
}

func (s *Server) Run() {
	s.GET("/login", s.Login)
	s.GET("/sendEmail", s.SendEmail)
	s.GET("/register", s.Register)

	if err := fasthttp.ListenAndServe(s.addr, s.Handler); err != nil {
		log.Fatalf("failed to listen error:%v\n", err)
		os.Exit(-1)
	}
}

func main() {
	opts := badger.DefaultOptions("./DB/userInfo.db")
	db, err := badger.Open(opts)
	if err != nil {
		log.Printf("init database error:%v\n", err)
		os.Exit(-1)
	}
	defer db.Close()

	s := &Server{":4545", fasthttprouter.Router{}, db}
	s.Run()
}

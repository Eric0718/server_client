package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"server/message"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/buaazp/fasthttprouter"
	"github.com/dgraph-io/badger"
	"github.com/valyala/fasthttp"
	"google.golang.org/grpc"
	"gopkg.in/gomail.v2"
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
	Addr string
	Rt   fasthttprouter.Router
	Db   *badger.DB
}

type resultInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	//Data    interface{} `json:"data"`
}

var usersInfo = []byte("userInfo")
var eAddr = []byte("email")
var tkName = []byte("tokenName")
var symb = []byte("symbol")

const (
	eml    = "email"
	psw    = "password"
	vfcode = "verifycode"
	addr   = "address"
	pri    = "private"
	tName  = "tokenName"
	sym    = "symbol"
	tot    = "total"

	notExist   = "NotExist"
	registerOk = "RegisterOk"
	loadOk     = "loadOk"
	leaderaddr = "106.12.186.120:8545" //address on blockchain line

	//from-email info
	user = "wallet@ktoken.ws"
	pass = "Ktoken88888"
	host = "smtp.qiye.aliyun.com"
	port = "465"
)

const minBalanceLimit = 500001

var sendcode string
var sendEmailAddr string

func (s *Server) Run() {
	s.Rt.GET("/login", s.Login)
	s.Rt.GET("/sendEmail", s.SendEmail)
	s.Rt.GET("/register", s.Register)
	s.Rt.GET("/creatContract", s.CreatContract)

	if err := fasthttp.ListenAndServe(s.Addr, s.Rt.Handler); err != nil {
		log.Fatalf("failed to listen error:%v\n", err)
		os.Exit(-1)
	}
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
	email := args.Peek(eml)
	password := args.Peek(psw)
	verifycode := args.Peek(vfcode)

	if sendEmailAddr != string(email) {
		log.Printf("email address not matched:first time[%s],second time[%s]\n", sendEmailAddr, string(email))
		result.Code = WrongEmail
		result.Message = fmt.Errorf("email address not matched:first time[%s],second time[%s]", sendEmailAddr, string(email)).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	if sendcode != string(verifycode) {
		log.Printf("verify code not matched:sendcode[%s],inputcode[%s]\n", sendcode, verifycode)
		result.Code = RegisterError
		result.Message = fmt.Errorf("verify code not matched:sendcode[%s],inputcode[%s]", sendcode, verifycode).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	statusCode := checkUserInfo(email, password)
	if statusCode != 0 {
		log.Printf("Register checkUserInfo: Wrong email or password.\n")
		result.Code = statusCode
		result.Message = "Wrong email or password"
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	//set email -> password
	if err := s.mset(usersInfo, email, password); err != nil {
		log.Printf("Set map '[email]password' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	//set email -> email
	if err := s.mset(eAddr, email, email); err != nil {
		log.Printf("Set map '[email]email' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	result.Code = SuccessCode
	result.Message = registerOk
	ctx.Response.SetStatusCode(http.StatusOK)
	sendEmailAddr = ""
	sendcode = ""
	log.Printf("Register user %s Ok!\n", email)
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
	emailTo := args.Peek(eml)

	//Alrady registered email can not be registered.
	value, err := s.mget(eAddr, emailTo)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("Register error:%v,emailTo:%v\n", err, string(value))
			result.Code = RegisterError
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusOK)
			return
		}
	}
	if len(value) > 0 {
		log.Printf("Register error:The email addrss[%v] already in use.\n", string(emailTo))
		result.Code = UsedEmail
		result.Message = fmt.Errorf("The email addrss[%v] already in use", string(emailTo)).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	//send email
	sendcode = genValidateCode(6) //随机生成6位验证码
	if err := s.sendEmail(string(emailTo), sendcode); err != nil {
		log.Printf("Register send email error:%v.\n", err)
		result.Code = SendEmailErr
		result.Message = fmt.Errorf("Send email error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	sendEmailAddr = string(emailTo)
	result.Code = SuccessCode
	result.Message = "SendEmailOk"
	ctx.Response.SetStatusCode(http.StatusOK)

	log.Printf("send email successfully! From: %v,To: %v\n", user, string(emailTo))
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
	email := args.Peek(eml)
	password := args.Peek(psw)

	value, err := s.mget(usersInfo, email)
	if err != nil {
		log.Printf("Login error:%v\n", err)
		if err.Error() == notExist {
			result.Code = UserNotExist
		} else {
			result.Code = LoadError
		}
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	if string(password) != string(value) {
		log.Printf("Login error: wrong password!\n")
		result.Code = WrongPassword
		result.Message = "WrongPassword"
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	result.Code = SuccessCode
	result.Message = loadOk
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
	address := args.Peek(addr)
	priv := args.Peek(pri)
	tokenName := args.Peek(tName) //need be keeped into db
	symbol := args.Peek(sym)      //need be keeped into db
	total := args.Peek(tot)

	// Existing tokenName can not be created.
	tvalue, err := s.mget(tkName, tokenName)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("CreatContract error:%v,tokenName:%v\n", err, string(tokenName))
			result.Code = CreatContractErr
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusOK)
			return
		}
	}
	if len(tvalue) > 0 {
		log.Printf("CreatContract error:The tokenName[%v] already Existing.\n", string(tokenName))
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("Error:The tokenName[%v] already Existing", string(tokenName)).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	// Existing Symbol can not be created.
	svalue, err := s.mget(symb, symbol)
	if err != nil {
		if err.Error() != notExist {
			log.Printf("CreatContract error:%v,symbol:%v\n", err, string(symbol))
			result.Code = CreatContractErr
			result.Message = err.Error()
			ctx.Response.SetStatusCode(http.StatusOK)
			return
		}
	}
	if len(svalue) > 0 {
		log.Printf("CreatContract error:The symbol[%v] already Existing.\n", string(symbol))
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("Error:The symbol[%v] already Existing", string(symbol)).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	conn, err := grpc.Dial(leaderaddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Printf("grpc Dial error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("grpc Dial error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	defer conn.Close()

	client := message.NewGreeterClient(conn)
	cx := context.Background()

	bl, err := client.GetBalance(cx, &message.ReqBalance{Address: string(address)})
	if err != nil {
		log.Printf("GetBalance error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract client.GetBalance error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	if bl.Balnce < uint64(minBalanceLimit) {
		log.Printf("Error: The address's Balnce[%v] should > [500001]\n", bl.Balnce)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract error: The address's Balnce[%v] should > [500001]", bl.Balnce).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	res, err := client.GetAddressNonceAt(cx, &message.ReqNonce{Address: string(address)})
	if err != nil {
		log.Printf("GetAddressNonceAt error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract GetAddressNonceAt error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	tt, err := strconv.ParseInt(string(total), 10, 64)
	if err != nil {
		log.Printf("strconv.ParseInt error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract strconv.ParseInt error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	ctc, err := client.CreateContract(cx, &message.ReqTokenCreate{
		From: string(address), To: "KtoCBhhMUrmcD5G5dmjLQJCiPeJLMfCt8EJE2ordaPc5B7d",
		Amount: uint64(minBalanceLimit), Nonce: res.Nonce,
		Fee: uint64(minBalanceLimit), Total: uint64(tt),
		Priv: string(priv), Symbol: string(symbol),
	})
	if err != nil {
		log.Printf("CreatContract error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("CreatContract error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	breakC := time.After(time.Second * 20) //check the creat hash whether on chain or not.
	for {
		select {
		case <-breakC: //time out,return
			log.Printf("CreatContract check creat hash error:timeout,creat hash:%v\n", ctc.Hash)
			result.Code = CreatContractErr
			result.Message = fmt.Errorf("CreatContract check creat hash error:timeout,creat hash:%v", ctc.Hash).Error()
			ctx.Response.SetStatusCode(http.StatusOK)
			return
		case <-time.After(time.Millisecond * 100):
			if len(ctc.Hash) > 0 {
				_, err := client.GetTxByHash(cx, &message.ReqTxByHash{Hash: ctc.Hash})
				if err != nil {
					continue
				}
			}
		}
		break
	}

	tct, err := client.MintToken(cx, &message.ReqTokenCreate{
		From: string(address), To: "KtoCBhhMUrmcD5G5dmjLQJCiPeJLMfCt8EJE2ordaPc5B7d",
		Amount: uint64(minBalanceLimit), Nonce: res.Nonce + 1,
		Fee: uint64(minBalanceLimit), Total: uint64(tt),
		Priv: string(priv), Symbol: string(symbol),
	})
	if err != nil {
		log.Printf("MintToken error:%v", err)
		result.Code = CreatContractErr
		result.Message = fmt.Errorf("MintToken error:%v", err).Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	breakCH := time.After(time.Second * 20) //check the mint hash whether on chain or not.
	for {
		select {
		case <-breakCH: //time out,return
			log.Printf("CreatContract check mint hash error:timeout,mint hash:%v\n", tct.Hash)
			result.Code = CreatContractErr
			result.Message = fmt.Errorf("CreatContract check mint hash error:timeout,mint hash:%v", tct.Hash).Error()
			ctx.Response.SetStatusCode(http.StatusOK)
			return
		case <-time.After(time.Millisecond * 100):
			if len(tct.Hash) > 0 {
				_, err := client.GetTxByHash(cx, &message.ReqTxByHash{Hash: tct.Hash})
				if err != nil {
					continue
				}
			}

		}
		break
	}

	//set tokenName -> tokenName
	if err := s.mset(tkName, tokenName, tokenName); err != nil {
		log.Printf("Set map '[tokenName]tokenName' error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}
	//set symbol -> symbol
	if err := s.mset(symb, symbol, symbol); err != nil {
		log.Printf("Set map '[symbol]symbol' error:%v\n", err)
		result.Code = CreatContractErr
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusOK)
		return
	}

	result.Code = SuccessCode
	result.Message = fmt.Errorf("CreatContract successfully,creat hash:%v,token hash:%v", ctc.Hash, tct.Hash).Error()
	ctx.Response.SetStatusCode(http.StatusOK)
	log.Printf("CreatContract successfully,creat hash:%v\ntoken hash:%v\n", ctc.Hash, tct.Hash)
	log.Printf("CreatContract Ok!\n")
	return
}

func (s *Server) sendEmail(mailTo string, code string) error {
	mailConn := map[string]string{
		"user": user,
		"pass": pass,
		"host": host,
		"port": port,
	}

	port, err := strconv.Atoi(mailConn["port"]) //转换端口类型为int
	if err != nil {
		return err
	}

	strMsg := `<div style="background:#f5f5f5;padding:48px 0;">
				<div style="width:665px;margin:0 auto;border:1px solid #dcdcdc;background:#ffffff">
				<h2 style="height:56px;line-height:56px;margin:0;color:#ffffff;font-size:20px;background:#40caba;padding-left:30px;font-weight:normal">【Kortho】</h2>
				<div style="padding:50px 0;margin:0 30px;font-size:13px;border-bottom:1px solid #ebebeb;">
				<h3 style="color:#000000;font-size:15px;margin:0;margin-bottom:4px;">亲爱的用户</h3>
					您正在验证身份，验证码是：
				<b style="font-size:26px;color:#40caba;margin-bottom:20px;display:block;margin-top:10px;">` + code + `</b>
					5分钟内有效，为了您的帐号安全，请勿泄露给他人。</div>
				<div style="color:#898989;font-size:10px;background:#fcfcfc;padding:18px 30px;">本邮件由系统自动发出，请勿直接回复。 谢谢！</div>
				</div>
				</div>`

	m := gomail.NewMessage()
	m.SetHeader("From", mailConn["user"])
	m.SetHeader("From", m.FormatAddress(mailConn["user"], "kortho官方"))
	m.SetHeader("To", mailTo)          //发送给多个用户
	m.SetHeader("Subject", "账户注册邮箱验证") //设置邮件主题
	m.SetBody("text/html", strMsg)     //设置邮件正文

	d := gomail.NewDialer(mailConn["host"], port, mailConn["user"], mailConn["pass"])
	err = d.DialAndSend(m)
	return err

}

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

func del(tx *badger.Txn, k []byte) error {
	return tx.Delete(k)
}

func (s *Server) mset(m, k, v []byte) error {
	tx := s.Db.NewTransaction(true)
	defer tx.Discard()
	if err := set(tx, eMapKey(m, k), v); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) mget(m, k []byte) ([]byte, error) {
	tx := s.Db.NewTransaction(true)
	defer tx.Discard()

	return get(tx, eMapKey(m, k))
}

func (s *Server) mdel(m, k []byte) error {
	tx := s.Db.NewTransaction(true)
	defer tx.Discard()
	return del(tx, eMapKey(m, k))
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

func E32func(a uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, a)
	return buf
}

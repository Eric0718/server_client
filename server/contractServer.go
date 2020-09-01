package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"unicode"

	"github.com/buaazp/fasthttprouter"
	"github.com/dgraph-io/badger"
	"github.com/valyala/fasthttp"
)

const (
	SuccessCode   = 0
	WrongPassword = 1
	UserNotExist  = 2
	RegisterError = 3
	LoadError     = 4
	UsedEmail     = 5
	WrongEmail    = 6
)

type Server struct {
	addr string
	fasthttprouter.Router
	db *badger.DB
}

type resultInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	//Data    interface{} `json:"data"`
}

func verifyEmailFormat(email string) bool {
	pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*` //匹配电子邮箱
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

func verifyPassword(s string) bool {
	var hasNumber, hasUpperCase, hasLowercase bool
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
	return hasNumber && hasUpperCase && hasLowercase //&& hasSpecial
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
		err = fmt.Errorf("UserNotExist")
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

	// statusCode := checkUserInfo(email, password)
	// if statusCode != 0 {
	// 	log.Printf("Register checkUserInfo: error code %v.\n", statusCode)
	// 	result.Code = statusCode
	// 	result.Message = "Wrong email or password"
	// 	ctx.Response.SetStatusCode(http.StatusBadRequest)
	// 	return
	// }

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

	//Alrady registered email can not be registered.
	value, err := s.mget([]byte("email"), email)
	if err != nil {
		if err.Error() != "UserNotExist" {
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

	//set email -> password
	if err := s.mset([]byte("userInfo"), email, password); err != nil {
		log.Printf("Set map '[email]password' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	//set email -> email
	if err := s.mset([]byte("email"), email, email); err != nil {
		log.Printf("Set map '[email]email' error:%v\n", err)
		result.Code = RegisterError
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	result.Code = SuccessCode
	result.Message = "RegisterOk"
	ctx.Response.SetStatusCode(http.StatusOK)
	log.Printf("Register Ok!\n")
	return
}

func (s *Server) Load(ctx *fasthttp.RequestCtx) {
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
	// 	log.Printf("Load checkUserInfo: error code %v.\n", statusCode)
	// 	result.Code = statusCode
	// 	result.Message = "WrongParameters"
	// 	ctx.Response.SetStatusCode(http.StatusBadRequest)
	// 	return
	// }

	// tx := s.db.NewTransaction(true)
	// defer tx.Discard()
	// value, err := get(tx, email)

	value, err := s.mget([]byte("userInfo"), email)
	if err != nil {
		log.Printf("Load error:%v\n", err)
		if err.Error() == "UserNotExist" {
			result.Code = UserNotExist
		} else {
			result.Code = LoadError
		}
		result.Message = err.Error()
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}

	if string(password) != string(value) {
		log.Printf("Load error: wrong password!\n")
		result.Code = WrongPassword
		result.Message = "WrongPassword"
		ctx.Response.SetStatusCode(http.StatusBadRequest)
		return
	}
	result.Code = SuccessCode
	result.Message = "LoadOk"
	ctx.Response.SetStatusCode(http.StatusOK)
	log.Printf("Load Ok!\n")
	return

}

func (s *Server) Run() {
	s.GET("/load", s.Load)
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

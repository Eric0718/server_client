package main

import (
	"log"
	"os"
	"server/server"

	"github.com/buaazp/fasthttprouter"
	"github.com/dgraph-io/badger"
)

func main() {
	opts := badger.DefaultOptions("./DB/userInfo.db")
	db, err := badger.Open(opts)
	if err != nil {
		log.Printf("init database error:%v\n", err)
		os.Exit(-1)
	}
	defer db.Close()

	s := &server.Server{Addr: ":4545", Rt: fasthttprouter.Router{}, Db: db}
	s.Run()
}

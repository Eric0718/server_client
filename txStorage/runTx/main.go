package main

import (
	"database/sql"
	"log"
	"os"
	"time"
	"txStorage"
)

const dsn = "root:123456@tcp(localhost:3306)/addr_txdata?charset=utf8"

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("Failed to connect database:", err)
		os.Exit(1)
	}

	var ts txStorage.TxStorage
	go ts.Run(db)

	for {
		time.Sleep(time.Second)
	}
}

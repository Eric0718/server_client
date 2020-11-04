module txStorage

go 1.13

require (
	github.com/astaxie/beego v1.12.2
	github.com/go-sql-driver/mysql v1.5.0
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.28.0
	google.golang.org/protobuf v1.23.0
	kortho v0.0.0
)

replace kortho v0.0.0 => ../kbft

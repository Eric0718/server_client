package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type resultInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	//Data    interface{} `json:"data"`
}

func main() {
	//使用Get方法获取服务器响应包数据
	//resp, err := http.Get("http://localhost:4545/register?email=123@qq&password=Lzl123456")
	resp, err := http.Get("http://localhost:4545/load?email=123@qq&password=Lzl12345")

	//resp, err := http.Get("http://localhost:4545/register?email=123456@qq&password=Lzl123456")
	//resp, err := http.Get("http://localhost:4545/load?email=email=123456@qq&password=Lzl12345")
	//resp, err := http.Get("http://localhost:4545/register?email=456@qq&password=Lzl123456")
	//resp, err := http.Get("http://localhost:4545/load?email=123@163.com&password=Lzl123456")

	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	// 获取服务器端读到的数据
	fmt.Println("Status = ", resp.Status)         // 状态
	fmt.Println("StatusCode = ", resp.StatusCode) // 状态码
	fmt.Println("Header = ", resp.Header)         // 响应头部
	fmt.Println("Body = ", resp.Body)             // 响应包体
	//读取body内的内容
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	res := &resultInfo{}
	err = json.Unmarshal(content, res)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(content))
	fmt.Printf("code:%v,message:%v\n", res.Code, res.Message)
}

package Utils

import (
	"fmt"
	"github.com/buger/jsonparser"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"time"
)

/**
***	dnslog API
**/
var client = &http.Client{
	Timeout: time.Second * 10,
}

func GetDnslogUrl() (string, string) {
	req, err := http.NewRequest("GET", "https://dnslog.org/new_gen", nil)
	if err != nil {
		err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		resp = NetWorkErrHandle(client, req, err)
		if resp == nil {
			fmt.Println("与 dnslog 平台网络不可达，请检查网络")
			return NETWORK_NOT_ACCESS, ""
		}
	}
	respBody, _ := io.ReadAll(resp.Body)
	data := []byte(respBody)
	var dnslog_domain string
	var dnslog_token string
	if domain_value, err := jsonparser.GetString(data, "domain"); err == nil {
		dnslog_domain = domain_value
	}
	if token_value, err := jsonparser.GetString(data, "token"); err == nil {
		dnslog_token = token_value
	}
	fmt.Println("[*] DNSLog Subdomain : ", dnslog_domain[0:len(dnslog_domain)-1], "\t", "token : ", dnslog_token)
	return string(dnslog_domain), dnslog_token
}

func GetDnslogRecord(dnslog_token string) string {
	dns_record_url := "https://dnslog.org/get_results?token=" + dnslog_token
	req, err := http.NewRequest("GET", dns_record_url, nil)
	if err != nil {
		err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		resp = NetWorkErrHandle(client, req, err)
		if resp == nil {
			fmt.Println("[!] 与 dnslog 网络不可达，请检查网络")
			return NETWORK_NOT_ACCESS
		}
	}
	body, _ := io.ReadAll(resp.Body)
	dns_48 := regexp.MustCompile(`48_.`)
	dns_68 := regexp.MustCompile(`68_.`)
	dns_80 := regexp.MustCompile(`80_.`)
	dns_83 := regexp.MustCompile(`83_.`)
	//fmt.Println(string(body))
	if string(body) == "null" {
		return ""
	} else {
		if dns_48.FindString(string(body)) != "" {
			return "48"
		}
		if dns_68.FindString(string(body)) != "" {
			return "68"
		}
		if dns_83.FindString(string(body)) != "" {
			return "83"
		}
		if dns_80.FindString(string(body)) != "" {
			return "80"
		}
		return "Recorded"
	}
}

func randCreator() string {
	str := "0123456789abcdefghigklmnopqrstuvwxyz"
	strList := []byte(str)
	result := []byte{}
	i := 0
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i < 12 {
		new := strList[r.Intn(len(strList))]
		result = append(result, new)
		i = i + 1
	}
	return string(result)
}

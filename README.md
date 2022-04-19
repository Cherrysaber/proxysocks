# proxysocks
**Go Proxy Protocol Library**

## Install
```bash
go get github.com/Cherrysaber/proxysocks
```

## Easy to Go

### socks5
```go
import "github.com/Cherrysaber/proxysocks/socks5"
...
func server(){
    ln,err := socks5.Listen("tcp", ":1080",nil)
    if err != nil { panic(err) }
    // hostPort为client请求代理的地址
    conn,hostPort,err := ln.Accept()
    if err != nil { panic(err) }
    go relay(conn,hostPort)... // 代理连接
}
func client(){
    // 通过socks5协议代理www.google.com:443
    conn,err := socks5.Dial("tcp","your_server.com:1234","www.google.com:443",nil)
    if err != nil { panic(err) }
    conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
    ...
}
```

### shadowsocks
```go
import "github.com/Cherrysaber/proxysocks/shadowsocks"
...
func server(){
    ln,err := shadowsocks.Listen("tcp", ":1234","method","password")
    if err != nil { panic(err) }
    // hostPort为client请求代理的地址
    conn,hostPort,err := ln.Accept()
    if err != nil { panic(err) }
    go relay(conn,hostPort)... // 代理连接
}
func client(){
    // 通过shadowsocks协议代理www.google.com:443
    conn,err := shadowsocks.Dial("tcp","your_server.com:1234","www.google.com:443","method","password")
    if err != nil { panic(err) }
    conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
    ...
}
```

### trojan
```go
import "github.com/Cherrysaber/proxysocks/trojan"
...
func server(){
    tlsConfig := &tls.Config{...} // 配置tls
    auth := trojan.NewAuthPasswordSlice([]string{"password"}, true) // trojan认证方式
    ln,err := trojan.Listen("tcp", ":443", auth, tlsConfig)
    if err != nil { panic(err) }
    // network为client请求代理的协议tcp or udp
    // hostPort为client请求代理的地址
    conn, network, hostPort, err := ln.Accept()
    if err == nil { ... //代理连接 }
    if err, ok := err.(trojan.AuthFailure); ok {
        // 认证失败返回AuthFailure错误
        // 重定向连接到网页
        // []byte(err) 为 trojan 已经读取的数据流
        go Redirect(conn, []byte(err))
        continue
    } 
    ... // 处理其他错误
}
func client(){
    // 通过trojan协议代理www.google.com:443
    tlsConfig := &tls.Config{...} // 配置tls
    conn,err := trojan.Dial("tcp", "your_server.com:443", "www.google.com:443", "password", tlsConfig)
    if err != nil { panic(err) }
    conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
    ...
}
```

- 所有包实现和**net**库一致接口Dial,Listen...
- 高聚合低耦合,基本只使用官方标准库,其余逻辑都内部自实现

## ToDo
- [x] Socks5
- [x] Shadosocks
- [x] Trojan
- [ ] Vmess
- [ ] Websocket 

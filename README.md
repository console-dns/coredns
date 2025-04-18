# coredns

## 安装说明

克隆 coredns 项目后在`plugin.cfg` 尾部添加如下内容

```text
console:github.com/console-dns/coredns
```

然后执行 `go generate`  ， 最后正常编译即可


## 使用说明

编辑 `Corefile` , 填入如下内容

```conf

.:53 {
  bind 0.0.0.0
  console . {
    server http://<your dns server>
    token <your dns server token>
    log error
  }
  forward . /etc/resolv.conf
}
```

最后正常启用即可
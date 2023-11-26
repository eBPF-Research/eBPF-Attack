
## 开发说明  
### 本地开发  
配置Go环境：  


编译并上传到测试Docker中
```
sudo apt install -y gcc-multilib

make && make install
```

编译单个项目：  
```
export BPF_CLANG=clang-13
cd attacks/cron
go generate
go build -o ../../bin/cron .
```

Copy到docker：  
```
$ make install
docker cp ebpf_attack ebpf_attack:/work/ebpf_attack
```

上传到transfer.sh，以便我们在测试机wget拉取eBPF程序，url被写到upload.txt里面：  
```
$ make upload
```

### 开发技巧  
eBPF Trace点先用bpftrace工具写脚本快速验证。再用eBPF-Go实现。   


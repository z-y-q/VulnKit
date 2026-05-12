// vk-sniff-state.js -- 灵眸 Chrome Extension
// Technology fingerprint rules database and confidence scoring

const TECH_SIGNATURES = [
  // ====== CMS ======
  {
    name: 'WordPress',
    category: 'CMS',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Pingback/i },
      { source: 'meta', type: 'regex', value: /generator.*wordpress/i },
      { source: 'body', type: 'regex', value: /wp-content\/|wp-includes\/|wp-json/i },
      { source: 'scriptSrc', type: 'regex', value: /wp-content\/|wp-includes\//i },
    ],
  },
  {
    name: 'Drupal',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /generator.*drupal/i },
      {
        source: 'body',
        type: 'regex',
        value: /Drupal\.settings|drupal\.js|sites\/default\/files/i,
      },
      { source: 'headers', type: 'regex', value: /X-Drupal-Cache|X-Generator.*Drupal/i },
    ],
  },
  {
    name: 'Joomla',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /generator.*joomla/i },
      { source: 'body', type: 'regex', value: /\/media\/jui\//i },
      { source: 'headers', type: 'regex', value: /X-Generator.*Joomla/i },
    ],
  },
  {
    name: 'Ghost',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /generator.*ghost/i },
      { source: 'headers', type: 'regex', value: /X-Ghost-Cache-Status/i },
    ],
  },
  {
    name: 'Shopify',
    category: 'CMS',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-ShopId|X-Shopify/i },
      { source: 'body', type: 'regex', value: /cdn\.shopify\.com/i },
      { source: 'scriptSrc', type: 'regex', value: /cdn\.shopify\.com/i },
    ],
  },
  {
    name: 'Magento',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /magento/i },
      {
        source: 'body',
        type: 'regex',
        value: /mage\/cache|skin\/frontend\/|Magento_GoogleAnalytics/i,
      },
      {
        source: 'cookies',
        type: 'regex',
        value: /mage-cache-storage-session|product_data_storage/i,
      },
    ],
  },
  {
    name: 'Typecho',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /generator.*typecho/i },
      { source: 'body', type: 'regex', value: /usr\/themes\//i },
    ],
  },
  {
    name: 'Hexo',
    category: 'CMS',
    matchers: [
      { source: 'meta', type: 'regex', value: /generator.*hexo/i },
      { source: 'body', type: 'regex', value: /hexo-theme|hexo\-generator/i },
    ],
  },

  // ====== Web Server ======
  {
    name: 'Nginx',
    category: 'Web 服务器',
    matchers: [{ source: 'headers', type: 'regex', value: /^server:\s*nginx/im }],
  },
  {
    name: 'Apache',
    category: 'Web 服务器',
    matchers: [{ source: 'headers', type: 'regex', value: /^server:\s*apache/im }],
  },
  {
    name: 'IIS',
    category: 'Web 服务器',
    matchers: [
      { source: 'headers', type: 'regex', value: /^server:\s*Microsoft-IIS/im },
      { source: 'headers', type: 'regex', value: /X-Powered-By.*ASP\.NET/im },
    ],
  },
  {
    name: 'OpenResty',
    category: 'Web 服务器',
    matchers: [{ source: 'headers', type: 'regex', value: /^server:\s*openresty/im }],
  },
  {
    name: 'Tomcat',
    category: 'Web 服务器',
    matchers: [
      { source: 'headers', type: 'regex', value: /Apache-Coyote/i },
      { source: 'headers', type: 'regex', value: /JSESSIONID/i },
    ],
  },
  {
    name: 'Caddy',
    category: 'Web 服务器',
    matchers: [{ source: 'headers', type: 'regex', value: /^server:\s*Caddy/im }],
  },

  // ====== Framework ======
  {
    name: 'Laravel',
    category: '框架',
    matchers: [
      { source: 'cookies', type: 'regex', value: /laravel_session/i },
      { source: 'headers', type: 'regex', value: /XSRF-TOKEN/i },
    ],
  },
  {
    name: 'Django',
    category: '框架',
    matchers: [
      { source: 'cookies', type: 'regex', value: /csrftoken/i },
      { source: 'headers', type: 'regex', value: /X-Frame-Options.*DENY/i },
    ],
  },
  {
    name: 'Spring Boot',
    category: '框架',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Application-Context/im },
      { source: 'body', type: 'regex', value: /Whitelabel Error Page/i },
      { source: 'headers', type: 'regex', value: /X-Trace-Id|X-Request-Id/i },
    ],
  },
  {
    name: 'Express',
    category: '框架',
    matchers: [{ source: 'headers', type: 'regex', value: /x-powered-by:\s*express/im }],
  },
  {
    name: 'Ruby on Rails',
    category: '框架',
    matchers: [
      { source: 'cookies', type: 'regex', value: /_rails_session|_session_id/i },
      { source: 'headers', type: 'regex', value: /X-Rack-Cache|X-Runtime/im },
    ],
  },
  {
    name: 'Next.js',
    category: '框架',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-nextjs-data|x-nextjs-version/im },
      { source: 'globals', type: 'equals', value: '__next' },
      { source: 'globals', type: 'equals', value: '__NEXT_DATA__' },
      { source: 'body', type: 'regex', value: /__next\//i },
      { source: 'scriptSrc', type: 'regex', value: /_next\//i },
    ],
  },
  {
    name: 'Nuxt.js',
    category: '框架',
    matchers: [
      { source: 'globals', type: 'equals', value: '__nuxt' },
      { source: 'globals', type: 'equals', value: '__NUXT__' },
      { source: 'meta', type: 'regex', value: /nuxt/i },
      { source: 'body', type: 'regex', value: /__nuxt\//i },
    ],
  },
  {
    name: 'Flask',
    category: '框架',
    matchers: [{ source: 'cookies', type: 'regex', value: /session=/i }],
  },
  {
    name: 'ThinkPHP',
    category: '框架',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Powered-By.*ThinkPHP/im },
      { source: 'cookies', type: 'regex', value: /thinkphp_session|think_var/i },
    ],
  },
  {
    name: 'Remix',
    category: '框架',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /build\/remix/i },
      { source: 'body', type: 'regex', value: /remix[_-](?:context|route|entry|manifest)/i },
      { source: 'globals', type: 'equals', value: '__remixContext' },
    ],
  },
  {
    name: 'Astro',
    category: '框架',
    matchers: [
      { source: 'body', type: 'regex', value: /astro-island|astro-slot|data-astro/i },
      { source: 'scriptSrc', type: 'regex', value: /_astro\//i },
    ],
  },
  {
    name: 'SvelteKit',
    category: '框架',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /\/_app\/immutable\//i },
      { source: 'globals', type: 'equals', value: '__sveltekit' },
      { source: 'body', type: 'regex', value: /sveltekit/i },
    ],
  },
  {
    name: 'Gin',
    category: '框架',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Powered-By.*Gin/im }],
  },
  {
    name: 'FastAPI',
    category: '框架',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Powered-By.*FastAPI|fastapi/im }],
  },
  {
    name: 'Fiber (Go)',
    category: '框架',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Powered-By.*Fiber/im }],
  },
  {
    name: 'NestJS',
    category: '框架',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Powered-By.*Express/i },
      { source: 'body', type: 'regex', value: /nest-[A-Z][a-zA-Z]+\.module|@nestjs\//i },
    ],
  },

  {
    name: '若依框架',
    category: '框架',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /\/ruoyi\//i },
      { source: 'meta', type: 'regex', value: /generator.*ruoyi/i },
      { source: 'body', type: 'regex', value: /ruoyi-sidebar|ruoyi-vue|ruoyi-layout/i },
      { source: 'body', type: 'regex', value: /若依|RuoYi\s*管理系统/i },
      { source: 'classNames', type: 'regex', value: /ruoyi-/i },
    ],
  },

  // ====== CDN / WAF ======
  {
    name: 'Cloudflare',
    category: 'CDN',
    matchers: [
      { source: 'headers', type: 'regex', value: /cf-ray|cf-cache-status/i },
      { source: 'headers', type: 'regex', value: /__cfduid/i },
      { source: 'cookies', type: 'regex', value: /__cfduid|cf_clearance/i },
    ],
  },
  {
    name: 'Akamai',
    category: 'CDN',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Akamai/i }],
  },
  {
    name: 'Incapsula/Imperva',
    category: 'CDN',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Iinfo|X-CDN/i },
      { source: 'cookies', type: 'regex', value: /incap_ses|visid_incap/i },
    ],
  },
  {
    name: 'Sucuri',
    category: 'CDN',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Sucuri-ID|X-Sucuri-Cache/i }],
  },
  {
    name: 'Fastly',
    category: 'CDN',
    matchers: [
      { source: 'headers', type: 'regex', value: /X-Fastly-Request-ID|X-Served-By.*fastly/i },
    ],
  },
  {
    name: 'AWS CloudFront',
    category: 'CDN',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-amz-cf-id|x-cloudfront/i },
      { source: 'headers', type: 'regex', value: /Via.*cloudfront/im },
    ],
  },
  {
    name: '阿里云 CDN',
    category: 'CDN',
    matchers: [{ source: 'headers', type: 'regex', value: /Via.*alicdn|ali-cdn/i }],
  },
  {
    name: '腾讯云 CDN',
    category: 'CDN',
    matchers: [{ source: 'headers', type: 'regex', value: /X-Cdn/i }],
  },

  // ====== JS Framework ======
  {
    name: 'Vue.js',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Vue' },
      { source: 'globals', type: 'equals', value: 'Vue (devtools)' },
      { source: 'globals', type: 'equals', value: 'Vue Router' },
      { source: 'globals', type: 'equals', value: 'Vue.js (DOM)' },
    ],
  },
  {
    name: 'React',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'React' },
      { source: 'globals', type: 'equals', value: 'ReactDOM' },
      { source: 'globals', type: 'equals', value: 'React DevTools' },
      { source: 'globals', type: 'equals', value: 'React (DOM)' },
    ],
  },
  {
    name: 'Angular',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'ng' },
      { source: 'globals', type: 'equals', value: 'angular' },
      { source: 'globals', type: 'equals', value: 'Angular (zone)' },
      { source: 'globals', type: 'equals', value: 'Angular (DOM)' },
    ],
  },
  {
    name: 'Svelte',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: '__svelte' },
      { source: 'globals', type: 'equals', value: '__sveltekit' },
      { source: 'body', type: 'regex', value: /class="[^"]*svelte-[^"]*"/i },
      { source: 'body', type: 'regex', value: /data-sveltekit-|__sveltekit/i },
      { source: 'scriptSrc', type: 'regex', value: /svelte\/internal|svelte\//i },
    ],
  },
  {
    name: 'Solid.js',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Solid' },
      { source: 'globals', type: 'equals', value: 'SolidMeta' },
      { source: 'body', type: 'regex', value: /data-solidjs|solid-[^-]/i },
      { source: 'scriptSrc', type: 'regex', value: /solid-js|solid\//i },
    ],
  },
  {
    name: 'Astro',
    category: '框架',
    matchers: [
      { source: 'body', type: 'regex', value: /astro-island|data-astro/i },
      { source: 'scriptSrc', type: 'regex', value: /_astro\//i },
      { source: 'meta', type: 'regex', value: /generator.*astro/i },
    ],
  },
  {
    name: 'Blazor',
    category: '框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Blazor' },
      { source: 'body', type: 'regex', value: /blazor\.webassembly|_framework\/blazor/i },
      { source: 'scriptSrc', type: 'regex', value: /_framework\/blazor/i },
    ],
  },
  {
    name: 'Ember',
    category: 'JS 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Ember' },
      { source: 'body', type: 'regex', value: /data-ember/i },
    ],
  },
  {
    name: 'Backbone.js',
    category: 'JS 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'Backbone' }],
  },

  // ====== JS Library ======
  {
    name: 'jQuery',
    category: 'JS 库',
    matchers: [
      { source: 'globals', type: 'equals', value: 'jQuery' },
      { source: 'globals', type: 'equals', value: 'jQuery ($)' },
    ],
  },
  {
    name: 'Lodash',
    category: 'JS 库',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Lodash' },
      { source: 'globals', type: 'equals', value: 'Lodash (_)' },
    ],
  },
  {
    name: 'Moment.js',
    category: 'JS 库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Moment.js' }],
  },
  {
    name: 'Axios',
    category: 'JS 库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Axios' }],
  },
  {
    name: 'Alpine.js',
    category: 'JS 库',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Alpine' },
      { source: 'body', type: 'regex', value: /x-data\s*=/i },
    ],
  },
  {
    name: 'GSAP',
    category: 'JS 库',
    matchers: [
      { source: 'globals', type: 'equals', value: 'gsap' },
      { source: 'body', type: 'regex', value: /gsap\.|TweenLite|TweenMax/i },
    ],
  },
  {
    name: 'anime.js',
    category: 'JS 库',
    matchers: [{ source: 'globals', type: 'equals', value: 'anime.js' }],
  },
  {
    name: 'Day.js',
    category: 'JS 库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Day.js' }],
  },
  {
    name: 'Chart.js',
    category: 'JS 库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Chart.js' }],
  },

  // ====== UI Framework ======
  {
    name: 'Bootstrap',
    category: 'UI 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Bootstrap' },
      { source: 'body', type: 'regex', value: /bootstrap[.\-]|data-bs-/i },
      { source: 'classNames', type: 'regex', value: /\bcontainer-fluid\b|\bnavbar\b|\bmodal\b/i },
    ],
  },
  {
    name: 'Element UI',
    category: 'UI 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'ELEMENT' }],
  },
  {
    name: 'Element Plus',
    category: 'UI 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'ElementPlus' }],
  },
  {
    name: 'Ant Design',
    category: 'UI 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'antd' }],
  },
  {
    name: 'Vuetify',
    category: 'UI 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'Vuetify' }],
  },
  {
    name: 'iView/ViewUI',
    category: 'UI 框架',
    matchers: [{ source: 'globals', type: 'equals', value: 'iview' }],
  },
  {
    name: 'Tailwind CSS',
    category: 'UI 框架',
    matchers: [
      {
        source: 'classNames',
        type: 'regex',
        value: /\bflex\b.*\bp-\d+\b|\bgrid\b.*\bcol-\w+-\d+\b|\btext-(?:xs|sm|base|lg|xl)\b/i,
      },
      { source: 'body', type: 'regex', value: /tailwindcss/i },
      { source: 'scriptSrc', type: 'regex', value: /tailwindcss/i },
    ],
  },
  {
    name: 'Bulma',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\bis-[\w-]+\b.*\bcolumn\b|\bnavbar\b/i },
      { source: 'meta', type: 'regex', value: /bulma/i },
    ],
  },
  {
    name: 'Naive UI',
    category: 'UI 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Naive UI' },
      { source: 'classNames', type: 'regex', value: /\bn-[a-z]+-\d+\b/i },
      { source: 'body', type: 'regex', value: /naive-ui|naive-ui-theme/i },
    ],
  },
  {
    name: 'TDesign',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\bt-[a-z]+__[a-z-]+\b/i },
      { source: 'body', type: 'regex', value: /tdesign|t-desgin/i },
      { source: 'scriptSrc', type: 'regex', value: /tdesign/i },
    ],
  },
  {
    name: 'Arco Design',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\barco-[a-z]+-[a-z]+\b/i },
      { source: 'body', type: 'regex', value: /arco-design/i },
      { source: 'scriptSrc', type: 'regex', value: /arco-design/i },
    ],
  },
  {
    name: 'Semi Design',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\bsemi-[a-z]+-[a-z]+\b/i },
      { source: 'body', type: 'regex', value: /semi-design|semi[-_]ui/i },
      { source: 'scriptSrc', type: 'regex', value: /semi[-_]design/i },
    ],
  },
  {
    name: 'Material UI',
    category: 'UI 框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Material-UI' },
      { source: 'classNames', type: 'regex', value: /\bMui[A-Z][a-zA-Z]+\b/ },
      { source: 'body', type: 'regex', value: /material-ui|MUI_/i },
    ],
  },
  {
    name: 'Chakra UI',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\bchakra-[a-z]+\b/i },
      { source: 'body', type: 'regex', value: /chakra-ui|__chakra/i },
    ],
  },
  {
    name: 'Radix UI',
    category: 'UI 框架',
    matchers: [
      { source: 'classNames', type: 'regex', value: /\bradix-[a-z]+\b/i },
      { source: 'body', type: 'regex', value: /radix-ui/i },
    ],
  },
  {
    name: 'Shadcn/ui',
    category: 'UI 框架',
    matchers: [
      {
        source: 'classNames',
        type: 'regex',
        value:
          /\b(?:border|bg|text|rounded|p|m|flex|gap)-(?:input|card|btn|badge|alert|dialog|toast|avatar|separator|sheet|dropdown|popover|tooltip|scroll|slider|switch|table|tabs|select|checkbox|radio|form|label|calendar|carousel|collapsible|accordion|command|sidebar|skeleton|sonner|aspect-ratio)\b/i,
      },
    ],
  },

  // ====== Analytics ======
  {
    name: 'Google Analytics',
    category: '分析',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Google Analytics (gtag)' },
      { source: 'globals', type: 'equals', value: 'Google Analytics (ga)' },
      { source: 'scriptSrc', type: 'regex', value: /google-analytics\.com|googletagmanager\.com/i },
      { source: 'body', type: 'regex', value: /google-analytics\.com|googletagmanager\.com/i },
    ],
  },
  {
    name: 'Google Tag Manager',
    category: '分析',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Google DataLayer' },
      { source: 'body', type: 'regex', value: /googletagmanager\.com\/gtm\.js/i },
    ],
  },
  {
    name: '百度统计',
    category: '分析',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Baidu Tongji' },
      { source: 'scriptSrc', type: 'regex', value: /hm\.baidu\.com/i },
    ],
  },
  {
    name: 'CNZZ',
    category: '分析',
    matchers: [
      { source: 'globals', type: 'equals', value: 'CNZZ' },
      { source: 'scriptSrc', type: 'regex', value: /cnzz\.com/i },
    ],
  },
  {
    name: 'Matomo',
    category: '分析',
    matchers: [
      { source: 'body', type: 'regex', value: /piwik\.php|matomo\.php/i },
      { source: 'globals', type: 'equals', value: 'Piwik' },
    ],
  },
  {
    name: 'Hotjar',
    category: '分析',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /static\.hotjar\.com/i },
      { source: 'cookies', type: 'regex', value: /_hjSessionUser|_hjid/i },
    ],
  },

  // ====== Maps ======
  {
    name: '高德地图',
    category: '地图',
    matchers: [{ source: 'globals', type: 'equals', value: 'AMap (高德)' }],
  },
  {
    name: '百度地图',
    category: '地图',
    matchers: [{ source: 'globals', type: 'equals', value: 'BMap (百度)' }],
  },
  {
    name: '腾讯地图',
    category: '地图',
    matchers: [{ source: 'globals', type: 'equals', value: 'TMap (腾讯)' }],
  },
  {
    name: 'Google Maps',
    category: '地图',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Google Maps' },
      { source: 'scriptSrc', type: 'regex', value: /maps\.googleapis\.com|maps\.google\.com/i },
    ],
  },

  // ====== Rich Text Editor ======
  {
    name: 'TinyMCE',
    category: '富文本编辑器',
    matchers: [
      { source: 'globals', type: 'equals', value: 'TinyMCE' },
      { source: 'classNames', type: 'regex', value: /\bmce-\w+/i },
    ],
  },
  {
    name: 'CKEditor',
    category: '富文本编辑器',
    matchers: [{ source: 'globals', type: 'equals', value: 'CKEDITOR' }],
  },
  {
    name: 'WangEditor',
    category: '富文本编辑器',
    matchers: [{ source: 'globals', type: 'equals', value: 'WangEditor' }],
  },
  {
    name: 'Quill',
    category: '富文本编辑器',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Quill' },
      { source: 'classNames', type: 'regex', value: /\bql-\w+/i },
    ],
  },

  // ====== Chart Library ======
  {
    name: 'ECharts',
    category: '图表库',
    matchers: [
      { source: 'globals', type: 'equals', value: 'ECharts' },
      { source: 'classNames', type: 'regex', value: /\b_?echarts_\w+/i },
    ],
  },
  {
    name: 'D3.js',
    category: '图表库',
    matchers: [{ source: 'globals', type: 'equals', value: 'D3.js' }],
  },
  {
    name: 'Highcharts',
    category: '图表库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Highcharts' }],
  },

  // ====== Crypto ======
  {
    name: 'CryptoJS',
    category: '加密库',
    matchers: [{ source: 'globals', type: 'equals', value: 'CryptoJS' }],
  },
  {
    name: 'jsencrypt',
    category: '加密库',
    matchers: [{ source: 'globals', type: 'equals', value: 'jsencrypt' }],
  },
  {
    name: 'Forge',
    category: '加密库',
    matchers: [{ source: 'globals', type: 'equals', value: 'Forge' }],
  },

  // ====== Monitoring ======
  {
    name: 'Sentry',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Sentry' },
      { source: 'scriptSrc', type: 'regex', value: /sentry\.io|cdn\.sentry-cdn\.com/i },
    ],
  },
  {
    name: 'New Relic',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'NREUM' },
      { source: 'scriptSrc', type: 'regex', value: /newrelic\.com/i },
    ],
  },
  {
    name: 'Datadog',
    category: '监控',
    matchers: [
      {
        source: 'scriptSrc',
        type: 'regex',
        value: /datadog[-_]browser|static\.datadog\.com|dd-browser/i,
      },
      { source: 'globals', type: 'equals', value: 'DD_RUM' },
    ],
  },
  {
    name: 'Dynatrace',
    category: '监控',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /dynatrace\.com|js-agent\.newrelic\.com/i },
      { source: 'cookies', type: 'regex', value: /dtCookie|dtSa|dtPC/i },
    ],
  },
  {
    name: 'AppDynamics',
    category: '监控',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /appdynamics\.com|cdn\.appdynamics\.com/i },
      { source: 'globals', type: 'equals', value: 'ADRUM' },
    ],
  },
  {
    name: 'Elastic APM',
    category: '监控',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /elastic-apm|elastic\.co\/apm/i },
      { source: 'headers', type: 'regex', value: /elastic-apm-traceparent/i },
    ],
  },
  {
    name: 'Honeybadger',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Honeybadger' },
      { source: 'scriptSrc', type: 'regex', value: /honeybadger\.io|js\.honeybadger\.io/i },
    ],
  },
  {
    name: 'Rollbar',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Rollbar' },
      { source: 'scriptSrc', type: 'regex', value: /rollbar\.com|cdnjs.*rollbar/i },
    ],
  },
  {
    name: 'Bugsnag',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Bugsnag' },
      { source: 'scriptSrc', type: 'regex', value: /bugsnag\.com|cdn\.bugsnag\.com/i },
    ],
  },
  {
    name: 'Instana',
    category: '监控',
    matchers: [
      { source: 'scriptSrc', type: 'regex', value: /instana\.io|eum\.instana\.io/i },
      { source: 'headers', type: 'regex', value: /X-Instana-T/i },
    ],
  },
  {
    name: 'Raygun',
    category: '监控',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Raygun' },
      { source: 'scriptSrc', type: 'regex', value: /raygun\.io|cdn\.raygun\.io/i },
    ],
  },

  // ====== Build Tools ======
  {
    name: 'Webpack',
    category: '构建工具',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Webpack' },
      { source: 'globals', type: 'equals', value: 'Webpack Modules' },
      { source: 'globals', type: 'equals', value: 'Webpack Chunk' },
    ],
  },
  {
    name: 'Vite',
    category: '构建工具',
    matchers: [{ source: 'globals', type: 'equals', value: 'Vite' }],
  },
  {
    name: 'Parcel',
    category: '构建工具',
    matchers: [{ source: 'globals', type: 'equals', value: 'Parcel' }],
  },

  // ====== Social SDK ======
  {
    name: '微信 JS-SDK',
    category: '社交 SDK',
    matchers: [
      { source: 'globals', type: 'equals', value: 'WeChat JS-SDK' },
      { source: 'globals', type: 'equals', value: 'WeChat Bridge' },
      { source: 'scriptSrc', type: 'regex', value: /res\.wx\.qq\.com\/open\/js\//i },
    ],
  },
  {
    name: '支付宝 JSAPI',
    category: '社交 SDK',
    matchers: [{ source: 'globals', type: 'equals', value: 'AlipayJSAPI' }],
  },
  {
    name: 'QQ SDK',
    category: '社交 SDK',
    matchers: [{ source: 'scriptSrc', type: 'regex', value: /open\.mobile\.qq\.com/i }],
  },

  // ====== Mobile Frameworks ======
  {
    name: 'Capacitor',
    category: '移动框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Capacitor' },
      { source: 'body', type: 'regex', value: /capacitor\.js|@capacitor\//i },
    ],
  },
  {
    name: 'Cordova',
    category: '移动框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'cordova' },
      { source: 'body', type: 'regex', value: /cordova\.js|cordova\.plugins/i },
    ],
  },
  {
    name: 'UniApp',
    category: '移动框架',
    matchers: [
      { source: 'body', type: 'regex', value: /uni-app|__uniappview/i },
      { source: 'globals', type: 'equals', value: 'uni' },
    ],
  },
  {
    name: 'React Native',
    category: '移动框架',
    matchers: [
      { source: 'globals', type: 'equals', value: '__ReactNative' },
      { source: 'body', type: 'regex', value: /react-native/i },
      { source: 'scriptSrc', type: 'regex', value: /react-native/i },
    ],
  },
  {
    name: 'Flutter',
    category: '移动框架',
    matchers: [
      { source: 'body', type: 'regex', value: /flutter|flutter_service_worker|_flutter/i },
      { source: 'scriptSrc', type: 'regex', value: /flutter|flutter\.js/i },
      { source: 'meta', type: 'regex', value: /flutter/i },
    ],
  },
  {
    name: 'Ionic',
    category: '移动框架',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Ionic' },
      { source: 'body', type: 'regex', value: /ionic/i },
      { source: 'scriptSrc', type: 'regex', value: /@ionic\//i },
    ],
  },

  // ====== Other ======
  {
    name: 'Socket.IO',
    category: '其他',
    matchers: [{ source: 'globals', type: 'equals', value: 'Socket.IO' }],
  },
  {
    name: 'GraphQL',
    category: '其他',
    matchers: [{ source: 'globals', type: 'equals', value: 'GraphQL' }],
  },
  {
    name: 'NProgress',
    category: '其他',
    matchers: [{ source: 'globals', type: 'equals', value: 'NProgress' }],
  },
  {
    name: 'Swiper',
    category: '其他',
    matchers: [{ source: 'globals', type: 'equals', value: 'Swiper' }],
  },
  {
    name: 'AOS',
    category: '其他',
    matchers: [{ source: 'globals', type: 'equals', value: 'AOS' }],
  },
  {
    name: 'Fancybox',
    category: '其他',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Fancybox' },
      { source: 'body', type: 'regex', value: /fancybox/i },
    ],
  },
  {
    name: 'Lightbox',
    category: '其他',
    matchers: [
      { source: 'globals', type: 'equals', value: 'Lightbox' },
      { source: 'body', type: 'regex', value: /lightbox/i },
    ],
  },

  // ====== Cloud Services ======
  {
    name: '阿里云 OSS',
    category: '云服务',
    matchers: [{ source: 'headers', type: 'regex', value: /x-oss-request-id|x-oss-hash/i }],
  },
  {
    name: '腾讯云 COS',
    category: '云服务',
    matchers: [{ source: 'headers', type: 'regex', value: /x-cos-request-id/i }],
  },
  {
    name: 'AWS S3',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-amz-request-id|x-amz-id-2/i },
      {
        source: 'body',
        type: 'regex',
        value: /s3\.amazonaws\.com|s3\.([a-z0-9-]+)\.amazonaws\.com/i,
      },
    ],
  },
  {
    name: 'Google Cloud Storage',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-goog-storage-class|x-guploader/i },
      { source: 'body', type: 'regex', value: /storage\.googleapis\.com/i },
    ],
  },
  {
    name: 'Azure Blob Storage',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-ms-blob-type|x-ms-lease-status/i },
      { source: 'body', type: 'regex', value: /\.blob\.core\.windows\.net/i },
    ],
  },
  {
    name: 'Vercel',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-vercel-id|x-now-trace/i },
      { source: 'body', type: 'regex', value: /vercel\.com|vercel-insights/i },
      { source: 'scriptSrc', type: 'regex', value: /vercel/i },
    ],
  },
  {
    name: 'Netlify',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /x-nf-request-id|x-netlify/i },
      { source: 'body', type: 'regex', value: /netlify/i },
    ],
  },
  {
    name: 'Cloudflare Pages',
    category: '云服务',
    matchers: [
      { source: 'headers', type: 'regex', value: /cf-ray/i },
      { source: 'body', type: 'regex', value: /pages\.dev|cloudflarepages\.com/i },
    ],
  },

  // ====== Security Headers ======
  {
    name: 'CSP',
    category: '安全头',
    matchers: [{ source: 'headers', type: 'regex', value: /content-security-policy/im }],
  },
  {
    name: 'HSTS',
    category: '安全头',
    matchers: [{ source: 'headers', type: 'regex', value: /strict-transport-security/im }],
  },
  {
    name: 'X-Frame-Options',
    category: '安全头',
    matchers: [{ source: 'headers', type: 'regex', value: /x-frame-options/im }],
  },
];

const CONFIDENCE_BASE_SCORES = {
  headers: 30,
  globals: 30,
  meta: 20,
  body: 20,
  cookies: 25,
  classNames: 15,
  ids: 15,
  scriptSrc: 18,
};

const CONFIDENCE_LEVELS = {
  strong: { min: 90, label: '强', color: '#10b981' },
  moderate: { min: 75, label: '稳', color: '#f59e0b' },
  weak: { min: 0, label: '弱', color: '#9ca3af' },
};

function scoreConfidence(matchedMatchers) {
  if (matchedMatchers.length === 0) return null;

  var baseScore = 0;
  var matchedSources = {};

  for (var i = 0; i < matchedMatchers.length; i++) {
    var m = matchedMatchers[i];
    var sourceScore = CONFIDENCE_BASE_SCORES[m.source] || 20;
    if (sourceScore > baseScore) baseScore = sourceScore;
    matchedSources[m.source] = true;
  }

  var sourceCount = Object.keys(matchedSources).length;
  var bonusMultiplier = 1 + (matchedMatchers.length - 1) * 0.2;
  var sourceBonus = (sourceCount - 1) * 4;
  var totalScore = Math.min(100, Math.round(baseScore * bonusMultiplier + sourceBonus));

  if (totalScore >= CONFIDENCE_LEVELS.strong.min) {
    return {
      score: totalScore,
      label: CONFIDENCE_LEVELS.strong.label,
      color: CONFIDENCE_LEVELS.strong.color,
    };
  }
  if (totalScore >= CONFIDENCE_LEVELS.moderate.min) {
    return {
      score: totalScore,
      label: CONFIDENCE_LEVELS.moderate.label,
      color: CONFIDENCE_LEVELS.moderate.color,
    };
  }
  return {
    score: totalScore,
    label: CONFIDENCE_LEVELS.weak.label,
    color: CONFIDENCE_LEVELS.weak.color,
  };
}

function extractVersion(techName, versions) {
  if (!versions || typeof versions !== 'object') return null;
  return versions[techName] || null;
}

export {
  TECH_SIGNATURES,
  CONFIDENCE_BASE_SCORES,
  CONFIDENCE_LEVELS,
  scoreConfidence,
  extractVersion,
};

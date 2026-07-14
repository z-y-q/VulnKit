// RuoYi MaR 路由字典
// 移植自 v5 vk-ruoyi-mar.js

export interface MarRouteEntry {
  path: string;
  title: string;
  component: string;
}

/** RuoYi 标准路由字典（33 个常见路由） */
export const RUOYI_KNOWN_ROUTES: MarRouteEntry[] = [
  { path: '/system/user', title: '用户管理', component: 'system/user/index' },
  { path: '/system/role', title: '角色管理', component: 'system/role/index' },
  { path: '/system/menu', title: '菜单管理', component: 'system/menu/index' },
  { path: '/system/dept', title: '部门管理', component: 'system/dept/index' },
  { path: '/system/dict', title: '字典管理', component: 'system/dict/index' },
  { path: '/system/config', title: '参数设置', component: 'system/config/index' },
  { path: '/system/notice', title: '通知公告', component: 'system/notice/index' },
  { path: '/system/log', title: '日志管理', component: 'system/log/index' },
  { path: '/system/log/login', title: '登录日志', component: 'system/log/login' },
  { path: '/system/log/oper', title: '操作日志', component: 'monitor/operlog/index' },
  { path: '/system/user/profile', title: '用户中心', component: 'system/user/profile/index' },
  { path: '/system/user/authRole', title: '角色授权', component: 'system/user/authRole' },
  { path: '/system/user/resetPwd', title: '重置密码', component: 'system/user/resetPwd' },
  { path: '/monitor/online', title: '在线用户', component: 'monitor/online/index' },
  { path: '/monitor/job', title: '定时任务', component: 'monitor/job/index' },
  { path: '/monitor/druid', title: '数据监控', component: 'monitor/druid/index' },
  { path: '/monitor/server', title: '服务监控', component: 'monitor/server/index' },
  { path: '/monitor/cache', title: '缓存监控', component: 'monitor/cache/index' },
  { path: '/monitor/cache/list', title: '缓存列表', component: 'monitor/cache/list' },
  { path: '/tool/gen', title: '代码生成', component: 'tool/gen/index' },
  { path: '/tool/swagger', title: '系统接口', component: 'tool/swagger/index' },
  { path: '/tool/build', title: '表单构建', component: 'tool/build/index' },
  { path: '/tool/edit', title: '表单编辑', component: 'tool/build/index' },
  { path: '/system/tenant', title: '租户管理', component: 'system/tenant/index' },
  { path: '/system/tenant/package', title: '租户套餐', component: 'system/tenant/package' },
  { path: '/system/oss', title: '文件管理', component: 'system/oss/index' },
  { path: '/system/oss/config', title: 'OSS配置', component: 'system/oss/config' },
  { path: '/system/post', title: '岗位管理', component: 'system/post/index' },
  { path: '/system/mail', title: '邮箱管理', component: 'system/mail/index' },
  { path: '/system/dict-data', title: '字典数据', component: 'system/dict/data' },
  { path: '/system/role/authUser', title: '分配用户', component: 'system/role/authUser' },
  { path: '/system/menu/menus', title: '菜单分配', component: 'system/role/menu' },
];

/** 云版/微服务专属端点字典（29 个） */
export const CLOUD_KNOWN_ROUTES: MarRouteEntry[] = [
  { path: '/actuator', title: 'Actuator', component: '' },
  { path: '/actuator/health', title: '健康检查', component: '' },
  { path: '/actuator/info', title: '应用信息', component: '' },
  { path: '/actuator/env', title: '环境变量', component: '' },
  { path: '/actuator/env/{name}', title: '环境变量详情', component: '' },
  { path: '/actuator/beans', title: 'Bean列表', component: '' },
  { path: '/actuator/mappings', title: '请求映射', component: '' },
  { path: '/actuator/gateway/routes', title: 'Gateway路由', component: '' },
  { path: '/actuator/configprops', title: '配置属性', component: '' },
  { path: '/actuator/metrics', title: '指标', component: '' },
  { path: '/actuator/trace', title: '链路追踪', component: '' },
  { path: '/actuator/loggers', title: '日志级别', component: '' },
  { path: '/actuator/scheduledtasks', title: '定时任务', component: '' },
  { path: '/actuator/threaddump', title: '线程转储', component: '' },
  { path: '/actuator/heapdump', title: '堆转储', component: '' },
  { path: '/actuator/prometheus', title: 'Prometheus', component: '' },
  { path: '/actuator/service-registry', title: '服务注册', component: '' },
  { path: '/nacos', title: 'Nacos', component: '' },
  { path: '/nacos/v1/ns/service/list', title: 'Nacos服务列表', component: '' },
  { path: '/nacos/v1/ns/instance/list', title: 'Nacos实例列表', component: '' },
  { path: '/nacos/v1/cs/configs', title: 'Nacos配置', component: '' },
  { path: '/nacos/v1/cs/configs?dataId=&group=&tenant=', title: 'Nacos配置查询', component: '' },
  { path: '/sentinel/dashboard', title: 'Sentinel控制台', component: '' },
  { path: '/swagger-ui.html', title: 'Swagger UI', component: '' },
  { path: '/v3/api-docs', title: 'OpenAPI 3', component: '' },
  { path: '/v2/api-docs', title: 'Swagger 2', component: '' },
  { path: '/v3/api-docs/swagger-config', title: 'Swagger配置', component: '' },
  { path: '/doc.html', title: 'Knife4j', component: '' },
  { path: '/seata', title: 'Seata', component: '' },
];

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <ShieldCheck :size="24" />
        <div>
          <h1>XDP Firewall</h1>
          <p>{{ health }}</p>
        </div>
      </div>
      <nav>
        <button v-for="item in tabs" :key="item.id" :class="{ active: tab === item.id }" @click="setTab(item.id)">
          <component :is="item.icon" :size="17" />
          <span>{{ t(item.label) }}</span>
        </button>
      </nav>
    </aside>

    <main>
      <header class="topbar">
        <div>
          <p class="eyebrow">{{ t("policy") }}</p>
          <div class="policy-row">
            <Input v-model="policy" aria-label="Policy name" />
            <Button variant="secondary" title="Refresh" @click="refreshAll">
              <RefreshCcw :size="16" />
            </Button>
            <Button title="Seed" @click="runAction(seedExample)">
              <DatabaseZap :size="16" />
            </Button>
          </div>
        </div>
        <div class="top-actions">
          <div class="token-row">
            <KeyRound :size="16" />
            <Input v-model="apiToken" type="password" aria-label="API token" :placeholder="t('apiToken')" @change="saveApiToken" />
          </div>
          <Select v-model="language" class="lang-select" aria-label="Language" @change="saveLanguage">
            <option value="zh">中文</option>
            <option value="en">English</option>
          </Select>
          <div class="version">
            <span>v{{ snapshot?.version ?? 0 }}</span>
            <Badge :tone="health === 'ok' ? 'green' : 'amber'">{{ health }}</Badge>
          </div>
        </div>
      </header>

      <section v-if="tab === 'rules'" class="panel">
        <div class="panel-head">
          <h2>{{ t("rules") }}</h2>
          <Button @click="runAction(createRule)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid rule-form">
          <Input v-model.number="ruleForm.priority" type="number" aria-label="Priority" />
          <Select v-model="ruleForm.action" aria-label="Action">
            <option value="deny">{{ t("deny") }}</option>
            <option value="allow">{{ t("allow") }}</option>
          </Select>
          <Input v-model="ruleForm.cidr" aria-label="CIDR" />
          <Select v-model="ruleForm.protocol" aria-label="Protocol">
            <option value="any">any</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </Select>
          <Input v-model="ruleForm.port" aria-label="Port" />
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("priority") }}</th>
              <th>{{ t("action") }}</th>
              <th>CIDR</th>
              <th>{{ t("protocol") }}</th>
              <th>{{ t("port") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="rule in rules" :key="rule.id">
              <td>{{ rule.priority }}</td>
              <td><Badge :tone="rule.action === 'deny' ? 'red' : 'green'">{{ rule.action }}</Badge></td>
              <td>{{ rule.cidr }}</td>
              <td>{{ rule.protocol ?? 'any' }}</td>
              <td>{{ rule.port ?? '*' }}</td>
              <td class="right"><Button variant="ghost" title="Delete" @click="runAction(() => deleteItem(`/policies/${policy}/rules/${rule.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="rulePage.page <= 1" @click="runAction(() => loadRules(rulePage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(rulePage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(rulePage)" @click="runAction(() => loadRules(rulePage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'geo'" class="panel">
        <div class="panel-head">
          <h2>{{ t("countries") }}</h2>
          <Button @click="runAction(createGeo)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid geo-form">
          <Input v-model="geoForm.country" aria-label="Country" />
          <Select v-model="geoForm.action" aria-label="Action">
            <option value="allow">{{ t("allow") }}</option>
            <option value="deny">{{ t("deny") }}</option>
          </Select>
          <Input v-model.number="geoForm.packets_per_second" type="number" aria-label="PPS" />
          <Input v-model.number="geoForm.burst" type="number" aria-label="Burst" />
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("country") }}</th>
              <th>{{ t("action") }}</th>
              <th>PPS</th>
              <th>{{ t("burst") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in geoCountries" :key="item.id">
              <td>{{ item.country }}</td>
              <td><Badge :tone="item.action === 'deny' ? 'red' : 'green'">{{ item.action }}</Badge></td>
              <td>{{ item.packets_per_second ?? 0 }}</td>
              <td>{{ item.burst ?? 0 }}</td>
              <td class="right"><Button variant="ghost" title="Delete" @click="runAction(() => deleteItem(`/policies/${policy}/geo-countries/${item.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="geoPage.page <= 1" @click="runAction(() => loadGeo(geoPage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(geoPage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(geoPage)" @click="runAction(() => loadGeo(geoPage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'threats'" class="panel">
        <div class="panel-head">
          <h2>{{ t("threatSources") }}</h2>
          <Button @click="runAction(createThreat)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid threat-form">
          <Input v-model="threatForm.name" aria-label="Name" />
          <Input v-model="threatForm.url" aria-label="URL" />
          <Select v-model="threatForm.format" aria-label="Format">
            <option value="cidr">cidr</option>
            <option value="ips">ips</option>
            <option value="ipsum">ipsum</option>
            <option value="spamhaus_drop">spamhaus_drop</option>
          </Select>
          <Input v-model.number="threatForm.min_score" type="number" aria-label="Score" />
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("name") }}</th>
              <th>{{ t("format") }}</th>
              <th>{{ t("score") }}</th>
              <th>URL</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="source in threatSources" :key="source.id">
              <td>{{ source.name }}</td>
              <td>{{ source.format }}</td>
              <td>{{ source.min_score ?? '' }}</td>
              <td class="clip">{{ source.url }}</td>
              <td class="right"><Button variant="ghost" title="Delete" @click="runAction(() => deleteItem(`/policies/${policy}/threat-sources/${source.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="threatPage.page <= 1" @click="runAction(() => loadThreats(threatPage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(threatPage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(threatPage)" @click="runAction(() => loadThreats(threatPage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'nodes'" class="panel">
        <div class="panel-head">
          <h2>{{ t("nodes") }}</h2>
          <Button variant="secondary" @click="runAction(() => loadNodes())"><RefreshCcw :size="16" /></Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("node") }}</th>
              <th>{{ t("policy") }}</th>
              <th>{{ t("interface") }}</th>
              <th>{{ t("version") }}</th>
              <th>{{ t("status") }}</th>
              <th>{{ t("seen") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="node in nodes" :key="node.node_id">
              <td>{{ node.node_id }}</td>
              <td>{{ node.policy_name }}</td>
              <td>{{ node.interface_name }}</td>
              <td>{{ node.last_applied_version }}</td>
              <td><Badge :tone="node.status === 'ok' ? 'green' : 'amber'">{{ node.status }}</Badge></td>
              <td>{{ node.last_seen_at }}</td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="nodePage.page <= 1" @click="runAction(() => loadNodes(nodePage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(nodePage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(nodePage)" @click="runAction(() => loadNodes(nodePage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <p v-if="error" class="error">{{ error }}</p>
    </main>

    <div v-if="authRequired" class="login-overlay">
      <section class="login-panel">
        <div class="login-head">
          <ShieldCheck :size="24" />
          <h2>XDP Firewall</h2>
        </div>
        <Input v-model="loginToken" type="password" aria-label="API token" :placeholder="t('apiToken')" @keyup.enter="runAction(submitLogin)" />
        <Button @click="runAction(submitLogin)">
          <KeyRound :size="16" />
          <span>{{ t("signIn") }}</span>
        </Button>
        <p v-if="loginError" class="error">{{ loginError }}</p>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { ChevronLeft, ChevronRight, DatabaseZap, Globe2, KeyRound, ListFilter, Plus, RefreshCcw, Server, ShieldCheck, Trash2 } from "lucide-vue-next";
import Badge from "./components/ui/Badge.vue";
import Button from "./components/ui/Button.vue";
import Input from "./components/ui/Input.vue";
import Select from "./components/ui/Select.vue";

type Rule = { id: number; priority: number; action: string; cidr: string; protocol?: string; port?: number };
type GeoCountry = { id: number; country: string; action: string; packets_per_second?: number; burst?: number };
type ThreatSource = { id: number; name: string; url: string; format: string; min_score?: number };
type NodeState = { node_id: string; policy_name: string; interface_name: string; last_applied_version: number; status: string; last_seen_at: string };
type Snapshot = { policy_name: string; version: number; rules: unknown[]; geo_countries: unknown[]; threat_sources: unknown[] };
type Page<T> = { items: T[]; total: number; page: number; page_size: number; total_pages: number };
type PageState = { page: number; total_pages: number; total: number };
type Lang = "zh" | "en";

const tabs = [
  { id: "rules", label: "rules", icon: ListFilter },
  { id: "geo", label: "countries", icon: Globe2 },
  { id: "threats", label: "threats", icon: ShieldCheck },
  { id: "nodes", label: "nodes", icon: Server }
] as const;

const tab = ref<(typeof tabs)[number]["id"]>("rules");
const language = ref<Lang>(localStorage.getItem("xdp-firewall-language") === "en" ? "en" : "zh");
const policy = ref("edge");
const health = ref("loading");
const error = ref("");
const apiToken = ref(localStorage.getItem("xdp-firewall-api-token") ?? "");
const loginToken = ref(apiToken.value);
const loginError = ref("");
const authRequired = ref(false);
const snapshot = ref<Snapshot | null>(null);
const rules = ref<Rule[]>([]);
const geoCountries = ref<GeoCountry[]>([]);
const threatSources = ref<ThreatSource[]>([]);
const nodes = ref<NodeState[]>([]);
const rulePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const geoPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const threatPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const nodePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });

const ruleForm = reactive({ priority: 10, action: "deny", cidr: "203.0.113.0/24", protocol: "any", port: "" });
const geoForm = reactive({ country: "CN", action: "allow", packets_per_second: 10000, burst: 20000 });
const threatForm = reactive({ name: "ipsum", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", format: "ipsum", min_score: 3 });

const actions = new Set(["allow", "deny"]);
const protocols = new Set(["any", "tcp", "udp", "icmp"]);
const threatFormats = new Set(["cidr", "ips", "ipsum", "spamhaus_drop"]);
const pageSize = 100;

const messages = {
  zh: {
    action: "动作",
    allow: "允许",
    apiToken: "API 令牌",
    authInvalid: "API 令牌缺失或无效",
    burst: "突发",
    countries: "国家",
    country: "国家",
    deny: "拒绝",
    format: "格式",
    interface: "网卡",
    name: "名称",
    node: "节点",
    nodes: "节点",
    page: "页",
    policy: "策略",
    port: "端口",
    priority: "优先级",
    protocol: "协议",
    policyName: "策略名称",
    rules: "规则",
    ruleAction: "规则动作",
    ruleCidr: "规则 CIDR",
    rulePriority: "规则优先级",
    ruleProtocol: "规则协议",
    score: "评分",
    seen: "最后在线",
    signIn: "登录",
    status: "状态",
    threats: "威胁",
    threatScore: "威胁评分",
    threatSourceFormat: "威胁源格式",
    threatSourceName: "威胁源名称",
    threatSourceUrl: "威胁源 URL",
    threatSources: "威胁源",
    total: "总数",
    version: "版本"
  },
  en: {
    action: "Action",
    allow: "allow",
    apiToken: "API token",
    authInvalid: "missing or invalid API token",
    burst: "Burst",
    countries: "Countries",
    country: "Country",
    deny: "deny",
    format: "Format",
    interface: "Interface",
    name: "Name",
    node: "Node",
    nodes: "Nodes",
    page: "Page",
    policy: "Policy",
    port: "Port",
    priority: "Priority",
    protocol: "Protocol",
    policyName: "Policy name",
    rules: "Rules",
    ruleAction: "Rule action",
    ruleCidr: "Rule CIDR",
    rulePriority: "Rule priority",
    ruleProtocol: "Rule protocol",
    score: "Score",
    seen: "Seen",
    signIn: "Sign in",
    status: "Status",
    threats: "Threats",
    threatScore: "Threat score",
    threatSourceFormat: "Threat source format",
    threatSourceName: "Threat source name",
    threatSourceUrl: "Threat source URL",
    threatSources: "Threat Sources",
    total: "Total",
    version: "Version"
  }
} as const;

const validationMessages = {
  zh: {
    anyPort: () => "端口要求协议为 tcp 或 udp",
    cidrAddress: (label: string) => `${label} 地址无效`,
    cidrPrefixInteger: (label: string) => `${label} 前缀长度必须是整数`,
    cidrPrefixRequired: (label: string) => `${label} 必须包含前缀长度`,
    countryCode: () => "国家必须是两个字母的 ISO 代码",
    httpUrl: (label: string) => `${label} 必须以 http:// 或 https:// 开头`,
    icmpPort: () => "ICMP 规则不能设置端口",
    integer: (label: string) => `${label} 必须是整数`,
    invalid: (label: string) => `${label} 无效`,
    ipv4Prefix: () => "IPv4 CIDR 前缀必须在 0 到 32 之间",
    ipv6Prefix: () => "IPv6 CIDR 前缀必须在 0 到 128 之间",
    minZero: (label: string) => `${label} 必须大于或等于 0`,
    portRange: () => "端口必须在 1 到 65535 之间",
    required: (label: string) => `${label} 不能为空`,
    validUrl: (label: string) => `${label} 必须是有效 URL`
  },
  en: {
    anyPort: () => "Port requires protocol tcp or udp",
    cidrAddress: (label: string) => `${label} address is invalid`,
    cidrPrefixInteger: (label: string) => `${label} prefix length must be an integer`,
    cidrPrefixRequired: (label: string) => `${label} must include a prefix length`,
    countryCode: () => "Country must be a two-letter ISO code",
    httpUrl: (label: string) => `${label} must start with http:// or https://`,
    icmpPort: () => "ICMP rules cannot set a port",
    integer: (label: string) => `${label} must be an integer`,
    invalid: (label: string) => `${label} is invalid`,
    ipv4Prefix: () => "IPv4 CIDR prefix must be between 0 and 32",
    ipv6Prefix: () => "IPv6 CIDR prefix must be between 0 and 128",
    minZero: (label: string) => `${label} must be greater than or equal to 0`,
    portRange: () => "Port must be between 1 and 65535",
    required: (label: string) => `${label} is required`,
    validUrl: (label: string) => `${label} must be a valid URL`
  }
} as const;

type TextKey = keyof typeof messages.zh;
type ValidationKey = keyof typeof validationMessages.zh;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  error.value = "";
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const token = apiToken.value.trim();
  if (token) {
    headers.set("authorization", `Bearer ${token}`);
  }
  const response = await fetch(apiUrl(path), {
    ...init,
    headers
  });
  if (response.status === 401) {
    authRequired.value = true;
    loginToken.value = apiToken.value;
    loginError.value = t("authInvalid");
    throw new Error(t("authInvalid"));
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || response.statusText);
  }
  return response.json() as Promise<T>;
}

function saveApiToken() {
  const token = apiToken.value.trim();
  if (token) {
    localStorage.setItem("xdp-firewall-api-token", token);
  } else {
    localStorage.removeItem("xdp-firewall-api-token");
  }
}

function saveLanguage() {
  localStorage.setItem("xdp-firewall-language", language.value);
}

function t(key: TextKey): string {
  return messages[language.value][key];
}

function v(key: ValidationKey, label = ""): string {
  return validationMessages[language.value][key](label);
}

function setTab(value: (typeof tabs)[number]["id"]) {
  tab.value = value;
  if (window.location.hash !== `#${value}`) {
    window.location.hash = value;
  }
}

function syncTabFromHash() {
  const value = window.location.hash.replace(/^#\/?/, "");
  if (tabs.some((item) => item.id === value)) {
    tab.value = value as (typeof tabs)[number]["id"];
  }
}

function apiUrl(path: string): string {
  const clean = path.replace(/^\/+/, "");
  return new URL(clean, pageBaseUrl()).toString();
}

function pageBaseUrl(): string {
  const href = window.location.href.split("#")[0];
  return href.endsWith("/") ? href : `${href.replace(/[^/]*$/, "")}`;
}

function pageQuery(page: number): string {
  return `page=${page}&page_size=${pageSize}`;
}

function updatePage<T>(state: PageState, data: Page<T>) {
  state.page = data.page;
  state.total_pages = data.total_pages;
  state.total = data.total;
}

function hasNext(state: PageState): boolean {
  return state.total_pages > 0 && state.page < state.total_pages;
}

function pageLabel(state: PageState): string {
  const totalPages = state.total_pages || 1;
  return `${t("page")} ${state.page}/${totalPages} · ${t("total")} ${state.total}`;
}

async function submitLogin() {
  loginError.value = "";
  apiToken.value = loginToken.value.trim();
  saveApiToken();
  authRequired.value = false;
  try {
    await refreshAll();
  } catch (err) {
    authRequired.value = true;
    loginError.value = err instanceof Error ? err.message : String(err);
  }
}

async function refreshAll() {
  try {
    await loadHealth();
    await loadPolicy();
    await loadRules();
    await loadGeo();
    await loadThreats();
    await loadNodes();
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  }
}

async function runAction(action: () => Promise<void>) {
  try {
    await action();
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  }
}

async function loadHealth() {
  const data = await api<{ status: string }>("health");
  health.value = data.status;
}

async function loadPolicy() {
  snapshot.value = await api<Snapshot>(`policies/${policy.value}`);
}

async function loadRules(page = rulePage.page) {
  const data = await api<Page<Rule>>(`policies/${policy.value}/rules?${pageQuery(page)}`);
  rules.value = data.items;
  updatePage(rulePage, data);
}

async function loadGeo(page = geoPage.page) {
  const data = await api<Page<GeoCountry>>(`policies/${policy.value}/geo-countries?${pageQuery(page)}`);
  geoCountries.value = data.items;
  updatePage(geoPage, data);
}

async function loadThreats(page = threatPage.page) {
  const data = await api<Page<ThreatSource>>(`policies/${policy.value}/threat-sources?${pageQuery(page)}`);
  threatSources.value = data.items;
  updatePage(threatPage, data);
}

async function loadNodes(page = nodePage.page) {
  const data = await api<Page<NodeState>>(`nodes?${pageQuery(page)}`);
  nodes.value = data.items;
  updatePage(nodePage, data);
}

async function seedExample() {
  const name = policyName();
  await api(`policies/${name}/seed-example`, { method: "POST" });
  await refreshAll();
}

async function createRule() {
  const name = policyName();
  const payload = validateRuleForm();
  await api(`policies/${name}/rules`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
}

async function createGeo() {
  const name = policyName();
  const payload = validateGeoForm();
  await api(`policies/${name}/geo-countries`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
}

async function createThreat() {
  const name = policyName();
  const payload = validateThreatForm();
  await api(`policies/${name}/threat-sources`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
}

async function deleteItem(path: string) {
  await api(path, { method: "DELETE" });
  await refreshAll();
}

onMounted(() => {
  syncTabFromHash();
  window.addEventListener("hashchange", syncTabFromHash);
  void refreshAll();
});

onBeforeUnmount(() => {
  window.removeEventListener("hashchange", syncTabFromHash);
});

function validateRuleForm() {
  const action = requireOneOf(t("ruleAction"), ruleForm.action, actions);
  const protocol = requireOneOf(t("ruleProtocol"), ruleForm.protocol, protocols);
  const cidr = requireCidr(t("ruleCidr"), ruleForm.cidr);
  const priority = requireInteger(t("rulePriority"), ruleForm.priority);
  const port = optionalPort(ruleForm.port);
  if (protocol === "icmp" && port !== null) {
    throwValidation(v("icmpPort"));
  }
  if (protocol === "any" && port !== null) {
    throwValidation(v("anyPort"));
  }
  return {
    priority,
    action,
    cidr,
    protocol,
    port
  };
}

function policyName(): string {
  return encodeURIComponent(requireText(t("policyName"), policy.value));
}

function validateGeoForm() {
  return {
    country: requireCountry(geoForm.country),
    action: requireOneOf(t("country"), geoForm.action, actions),
    packets_per_second: optionalNonNegativeInteger("PPS", geoForm.packets_per_second),
    burst: optionalNonNegativeInteger(t("burst"), geoForm.burst)
  };
}

function validateThreatForm() {
  const name = requireText(t("threatSourceName"), threatForm.name);
  const url = requireHttpUrl(t("threatSourceUrl"), threatForm.url);
  const format = requireOneOf(t("threatSourceFormat"), threatForm.format, threatFormats);
  return {
    name,
    url,
    format,
    min_score: optionalNonNegativeInteger(t("threatScore"), threatForm.min_score)
  };
}

function requireText(label: string, value: unknown): string {
  const text = String(value ?? "").trim();
  if (!text) {
    throwValidation(v("required", label));
  }
  return text;
}

function requireOneOf(label: string, value: unknown, allowed: Set<string>): string {
  const text = requireText(label, value).toLowerCase();
  if (!allowed.has(text)) {
    throwValidation(v("invalid", label));
  }
  return text;
}

function requireInteger(label: string, value: unknown): number {
  const number = Number(value);
  if (!Number.isInteger(number)) {
    throwValidation(v("integer", label));
  }
  return number;
}

function optionalNonNegativeInteger(label: string, value: unknown): number | null {
  if (value === "" || value === null || value === undefined) {
    return null;
  }
  const number = requireInteger(label, value);
  if (number < 0) {
    throwValidation(v("minZero", label));
  }
  return number;
}

function optionalPort(value: unknown): number | null {
  if (value === "" || value === null || value === undefined) {
    return null;
  }
  const port = requireInteger(t("port"), value);
  if (port < 1 || port > 65535) {
    throwValidation(v("portRange"));
  }
  return port;
}

function requireCountry(value: unknown): string {
  const country = requireText("Country", value).toUpperCase();
  if (!/^[A-Z]{2}$/.test(country)) {
    throwValidation(v("countryCode"));
  }
  return country;
}

function requireHttpUrl(label: string, value: unknown): string {
  const text = requireText(label, value);
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    throwValidation(v("validUrl", label));
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throwValidation(v("httpUrl", label));
  }
  return text;
}

function requireCidr(label: string, value: unknown): string {
  const cidr = requireText(label, value);
  const parts = cidr.split("/");
  if (parts.length !== 2) {
    throwValidation(v("cidrPrefixRequired", label));
  }
  const prefix = Number(parts[1]);
  if (!Number.isInteger(prefix)) {
    throwValidation(v("cidrPrefixInteger", label));
  }
  if (isIpv4(parts[0])) {
    if (prefix < 0 || prefix > 32) {
      throwValidation(v("ipv4Prefix"));
    }
    return cidr;
  }
  if (isIpv6(parts[0])) {
    if (prefix < 0 || prefix > 128) {
      throwValidation(v("ipv6Prefix"));
    }
    return cidr;
  }
  throwValidation(v("cidrAddress", label));
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === String(Number(part));
  });
}

function isIpv6(value: string): boolean {
  if (!value.includes(":")) {
    return false;
  }
  const parts = value.split("::");
  if (parts.length > 2) {
    return false;
  }
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts[1] ? parts[1].split(":") : [];
  const groups = [...left, ...right];
  if (groups.some((group) => !/^[0-9a-fA-F]{1,4}$/.test(group))) {
    return false;
  }
  return parts.length === 2 ? groups.length < 8 : groups.length === 8;
}

function throwValidation(message: string): never {
  error.value = message;
  throw new Error(message);
}
</script>

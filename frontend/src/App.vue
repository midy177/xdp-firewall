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
          <p class="eyebrow">{{ t("firewall") }}</p>
          <div class="policy-row">
            <Button variant="secondary" :title="t('refresh')" :disabled="actionBusy" @click="runAction(refreshAll)">
              <RefreshCcw :class="{ spin: loading }" :size="16" />
            </Button>
            <Button :title="t('seed')" :disabled="actionBusy" @click="runAction(seedExample)">
              <DatabaseZap :size="16" />
            </Button>
          </div>
        </div>
        <div class="top-actions">
          <div class="token-row">
            <KeyRound :size="16" />
            <Input v-model="apiToken" type="password" aria-label="API token" :placeholder="t('apiToken')" />
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

      <div class="summary-grid">
        <div class="summary-item">
          <span>{{ t("rules") }}</span>
          <strong>{{ rulePage.total }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("countries") }}</span>
          <strong>{{ geoPage.total }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("threatSources") }}</span>
          <strong>{{ threatPage.total }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("dynamicDefense") }}</span>
          <strong>{{ dynamicDefense.enabled ? t("enabledShort") : t("disabledShort") }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("trustedCidrs") }}</span>
          <strong>{{ trustedPage.total }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("nodes") }}</span>
          <strong>{{ nodePage.total }}</strong>
        </div>
      </div>

      <section class="priority-strip" :aria-label="t('priorityOrder')">
        <div v-for="item in priorityOrder" :key="item.rank" class="priority-step">
          <strong>{{ item.rank }}</strong>
          <div>
            <span>{{ t(item.label) }}</span>
            <small>{{ t(item.detail) }}</small>
          </div>
        </div>
      </section>

      <section v-if="tab === 'rules'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("rules") }}</h2>
            <p>{{ t("rulesHint") }}</p>
          </div>
        </div>
        <div class="form-grid rule-form">
          <label class="field">
            <span>{{ t("priority") }}</span>
            <Input v-model.number="ruleForm.priority" type="number" aria-label="Priority" />
          </label>
          <label class="field">
            <span>{{ t("action") }}</span>
            <Select v-model="ruleForm.action" aria-label="Action">
              <option value="deny">{{ t("deny") }}</option>
              <option value="allow">{{ t("allow") }}</option>
            </Select>
          </label>
          <label class="field">
            <span>CIDR</span>
            <Input v-model="ruleForm.cidr" aria-label="CIDR" placeholder="203.0.113.0/24" />
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="ruleForm.protocol" aria-label="Protocol">
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input v-model="ruleForm.port" aria-label="Port" placeholder="80" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy" @click="runAction(createRule)"><Plus :size="16" /></Button>
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
            <tr v-if="!loading && rules.length === 0">
              <td colspan="6" class="empty">{{ t("emptyRules") }}</td>
            </tr>
            <tr v-for="rule in rules" :key="rule.id">
              <td>
                <div class="priority-cell">
                  <span>{{ rule.priority }}</span>
                  <Badge v-if="isHighestRule(rule)" tone="amber">{{ t("highest") }}</Badge>
                </div>
              </td>
              <td><Badge :tone="rule.action === 'deny' ? 'red' : 'green'">{{ rule.action }}</Badge></td>
              <td>{{ rule.cidr }}</td>
              <td>{{ rule.protocol ?? 'any' }}</td>
              <td>{{ rule.port ?? '*' }}</td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/rules/${rule.id}`))"><Trash2 :size="15" /></Button></td>
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
          <div>
            <h2>{{ t("countries") }}</h2>
            <p>{{ t("countriesHint") }}</p>
          </div>
        </div>
        <div class="form-grid geo-form">
          <label class="field">
            <span>{{ t("country") }}</span>
            <Select v-model="geoForm.country" aria-label="Country">
              <option v-for="country in countries" :key="country.code" :value="country.code">{{ countryLabel(country) }}</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("action") }}</span>
            <Select v-model="geoForm.action" aria-label="Action">
              <option value="allow">{{ t("allow") }}</option>
              <option value="deny">{{ t("deny") }}</option>
            </Select>
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy" @click="runAction(createGeo)"><Plus :size="16" /></Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("country") }}</th>
              <th>{{ t("action") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!loading && geoCountries.length === 0">
              <td colspan="3" class="empty">{{ t("emptyCountries") }}</td>
            </tr>
            <tr v-for="item in geoCountries" :key="item.id">
              <td>{{ item.country }}</td>
              <td><Badge :tone="item.action === 'deny' ? 'red' : 'green'">{{ item.action }}</Badge></td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/geo-countries/${item.id}`))"><Trash2 :size="15" /></Button></td>
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
          <div>
            <h2>{{ t("threatSources") }}</h2>
            <p>{{ t("threatsHint") }}</p>
          </div>
        </div>
        <div class="form-grid threat-form">
          <label class="field">
            <span>{{ t("name") }}</span>
            <Input v-model="threatForm.name" aria-label="Name" placeholder="ipsum" />
          </label>
          <label class="field">
            <span>URL</span>
            <Input v-model="threatForm.url" aria-label="URL" placeholder="https://..." />
          </label>
          <label class="field">
            <span>{{ t("format") }}</span>
            <Select v-model="threatForm.format" aria-label="Format">
              <option value="cidr">cidr</option>
              <option value="ips">ips</option>
              <option value="ipsum">ipsum</option>
              <option value="spamhaus_drop">spamhaus_drop</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("score") }}</span>
            <Input v-model.number="threatForm.min_score" type="number" aria-label="Score" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy" @click="runAction(createThreat)"><Plus :size="16" /></Button>
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
            <tr v-if="!loading && threatSources.length === 0">
              <td colspan="5" class="empty">{{ t("emptyThreats") }}</td>
            </tr>
            <tr v-for="source in threatSources" :key="source.id">
              <td>{{ source.name }}</td>
              <td>{{ source.format }}</td>
              <td>{{ source.min_score ?? '' }}</td>
              <td class="clip">{{ source.url }}</td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/threat-sources/${source.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="threatPage.page <= 1" @click="runAction(() => loadThreats(threatPage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(threatPage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(threatPage)" @click="runAction(() => loadThreats(threatPage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'defense'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("dynamicDefense") }}</h2>
            <p>{{ t("dynamicDefenseHint") }}</p>
          </div>
        </div>
        <div class="form-grid defense-form">
          <label class="check-field">
            <input v-model="dynamicDefense.enabled" type="checkbox" />
            <span>{{ t("enabled") }}</span>
          </label>
          <label class="check-field">
            <input v-model="dynamicDefense.ip_rate_limit_enabled" type="checkbox" />
            <span>ip_rate_limit</span>
          </label>
          <label class="field">
            <span>{{ t("ipPps") }}</span>
            <Input v-model.number="dynamicDefense.ip_packets_per_second" type="number" aria-label="IP PPS" />
          </label>
          <label class="field">
            <span>{{ t("ipBurst") }}</span>
            <Input v-model.number="dynamicDefense.ip_burst" type="number" aria-label="IP burst" />
          </label>
          <label class="check-field">
            <input v-model="dynamicDefense.flood_enabled" type="checkbox" />
            <span>flood</span>
          </label>
          <label class="field">
            <span>{{ t("floodPps") }}</span>
            <Input v-model.number="dynamicDefense.flood_packets_per_second" type="number" aria-label="Flood PPS" />
          </label>
          <label class="field">
            <span>{{ t("floodBurst") }}</span>
            <Input v-model.number="dynamicDefense.flood_burst" type="number" aria-label="Flood burst" />
          </label>
          <label class="field">
            <span>{{ t("blockSeconds") }}</span>
            <Input v-model.number="dynamicDefense.flood_block_seconds" type="number" aria-label="Flood block seconds" />
          </label>
          <Button class="form-submit" :title="t('save')" :disabled="actionBusy" @click="runAction(saveDynamicDefense)"><DatabaseZap :size="16" /></Button>
        </div>
      </section>

      <section v-if="tab === 'trusted'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("trustedCidrs") }}</h2>
            <p>{{ t("trustedCidrsHint") }}</p>
          </div>
        </div>
        <div class="form-grid trusted-form">
          <label class="field">
            <span>CIDR</span>
            <Input v-model="trustedForm.cidr" aria-label="Trusted CIDR" placeholder="10.0.0.0/8" />
          </label>
          <label class="field">
            <span>{{ t("comment") }}</span>
            <Input v-model="trustedForm.comment" aria-label="Comment" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy" @click="runAction(createTrustedCidr)"><Plus :size="16" /></Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>CIDR</th>
              <th>{{ t("status") }}</th>
              <th>{{ t("comment") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!loading && trustedCidrs.length === 0">
              <td colspan="4" class="empty">{{ t("emptyTrustedCidrs") }}</td>
            </tr>
            <tr v-for="item in trustedCidrs" :key="item.id">
              <td>{{ item.cidr }}</td>
              <td><Badge :tone="item.enabled ? 'green' : 'amber'">{{ item.enabled ? t("enabledShort") : t("disabledShort") }}</Badge></td>
              <td class="clip">{{ item.comment ?? '' }}</td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/trusted-cidrs/${item.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="trustedPage.page <= 1" @click="runAction(() => loadTrustedCidrs(trustedPage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(trustedPage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(trustedPage)" @click="runAction(() => loadTrustedCidrs(trustedPage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'nodes'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("nodes") }}</h2>
            <p>{{ t("nodesHint") }}</p>
          </div>
          <Button variant="secondary" :disabled="actionBusy" @click="runAction(() => loadNodes())"><RefreshCcw :class="{ spin: loading }" :size="16" /></Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("node") }}</th>
              <th>{{ t("interface") }}</th>
              <th>{{ t("version") }}</th>
              <th>{{ t("status") }}</th>
              <th>{{ t("seen") }}</th>
              <th>{{ t("error") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!loading && nodes.length === 0">
              <td colspan="6" class="empty">{{ t("emptyNodes") }}</td>
            </tr>
            <tr v-for="node in nodes" :key="node.node_id">
              <td>{{ node.node_id }}</td>
              <td>{{ node.interface_name }}</td>
              <td>{{ node.last_applied_version }}</td>
              <td><Badge :tone="node.status === 'ok' ? 'green' : 'amber'">{{ node.status }}</Badge></td>
              <td>{{ node.last_seen_at }}</td>
              <td class="clip">{{ node.error ?? '' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="nodePage.page <= 1" @click="runAction(() => loadNodes(nodePage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(nodePage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(nodePage)" @click="runAction(() => loadNodes(nodePage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <div v-if="loading" class="loading-bar"><span></span></div>
      <p v-if="error" class="error">{{ error }}</p>
      <p v-else-if="notice" class="notice">{{ notice }}</p>
    </main>

    <div v-if="authRequired" class="login-overlay">
      <section class="login-panel">
        <div class="login-head">
          <ShieldCheck :size="24" />
          <h2>XDP Firewall</h2>
        </div>
        <Input v-model="loginToken" type="password" aria-label="API token" :placeholder="t('apiToken')" @keyup.enter="runAction(submitLogin)" />
        <Button :disabled="actionBusy" @click="runAction(submitLogin)">
          <KeyRound :size="16" />
          <span>{{ t("signIn") }}</span>
        </Button>
        <p v-if="loginError" class="error">{{ loginError }}</p>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { ChevronLeft, ChevronRight, DatabaseZap, Globe2, KeyRound, ListFilter, Plus, RefreshCcw, Server, ShieldCheck, Trash2 } from "lucide-vue-next";
import Badge from "./components/ui/Badge.vue";
import Button from "./components/ui/Button.vue";
import Input from "./components/ui/Input.vue";
import Select from "./components/ui/Select.vue";

type Rule = { id: number; priority: number; action: string; cidr: string; protocol?: string; port?: number };
type GeoCountry = { id: number; country: string; action: string; packets_per_second?: number; burst?: number };
type ThreatSource = { id: number; name: string; url: string; format: string; min_score?: number };
type TrustedCidr = { id: number; cidr: string; enabled: boolean; comment?: string };
type CountryOption = { code: string; name: string };
type DynamicDefense = {
  enabled: boolean;
  ip_rate_limit_enabled: boolean;
  ip_packets_per_second?: number | null;
  ip_burst?: number | null;
  flood_enabled: boolean;
  flood_packets_per_second?: number | null;
  flood_burst?: number | null;
  flood_block_seconds?: number | null;
};
type NodeState = { node_id: string; interface_name: string; last_applied_version: number; status: string; last_seen_at: string; error?: string };
type Snapshot = { version: number; rules: unknown[]; geo_countries: unknown[]; dynamic_defense: DynamicDefense; trusted_cidrs: unknown[]; threat_sources: unknown[] };
type Page<T> = { items: T[]; total: number; page: number; page_size: number; total_pages: number };
type PageState = { page: number; total_pages: number; total: number };
type Lang = "zh" | "en";

const tabs = [
  { id: "rules", label: "rules", icon: ListFilter },
  { id: "geo", label: "countries", icon: Globe2 },
  { id: "threats", label: "threats", icon: ShieldCheck },
  { id: "defense", label: "dynamicDefense", icon: ShieldCheck },
  { id: "trusted", label: "trustedCidrs", icon: KeyRound },
  { id: "nodes", label: "nodes", icon: Server }
] as const;

const tab = ref<(typeof tabs)[number]["id"]>("rules");
const language = ref<Lang>(localStorage.getItem("xdp-firewall-language") === "en" ? "en" : "zh");
const health = ref("loading");
const error = ref("");
const notice = ref("");
const loading = ref(false);
const actionBusy = ref(false);
const apiToken = ref("");
const loginToken = ref(apiToken.value);
const loginError = ref("");
const authRequired = ref(false);
const snapshot = ref<Snapshot | null>(null);
const rules = ref<Rule[]>([]);
const geoCountries = ref<GeoCountry[]>([]);
const threatSources = ref<ThreatSource[]>([]);
const trustedCidrs = ref<TrustedCidr[]>([]);
const countries = ref<CountryOption[]>([]);
const nodes = ref<NodeState[]>([]);
const rulePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const geoPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const threatPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const trustedPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const nodePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });

const ruleForm = reactive({ priority: 10, action: "deny", cidr: "203.0.113.0/24", protocol: "any", port: "" });
const geoForm = reactive({ country: "CN", action: "allow" });
const threatForm = reactive({ name: "ipsum", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", format: "ipsum", min_score: 3 });
const trustedForm = reactive({ cidr: "10.0.0.0/8", comment: "" });
const dynamicDefense = reactive<DynamicDefense>({
  enabled: true,
  ip_rate_limit_enabled: true,
  ip_packets_per_second: 5000,
  ip_burst: 10000,
  flood_enabled: true,
  flood_packets_per_second: 20000,
  flood_burst: 40000,
  flood_block_seconds: 60
});

const actions = new Set(["allow", "deny"]);
const protocols = new Set(["any", "tcp", "udp", "icmp"]);
const threatFormats = new Set(["cidr", "ips", "ipsum", "spamhaus_drop"]);
const pageSize = 100;
const authHeader = "Authorization";
const apiTokenHeader = "X-API-Token";

const messages = {
  zh: {
    action: "动作",
    add: "添加",
    allow: "允许",
    apiToken: "API 令牌",
    authInvalid: "API 令牌缺失或无效",
    blockSeconds: "封禁秒数",
    burst: "突发",
    comment: "备注",
    confirmDelete: "确认删除这条配置？",
    countries: "国家",
    countriesHint: "按国家代码配置允许或拒绝",
    country: "国家",
    delete: "删除",
    disabledShort: "关",
    dynamicDefense: "动态防御",
    dynamicDefenseHint: "配置全局每源 IP 限流和 flood 临时封禁",
    deny: "拒绝",
    emptyCountries: "暂无国家规则",
    emptyNodes: "暂无节点心跳",
    emptyRules: "暂无普通防火墙规则",
    emptyThreats: "暂无威胁源",
    emptyTrustedCidrs: "暂无白名单",
    enabled: "启用",
    enabledShort: "开",
    error: "错误",
    floodBurst: "Flood 突发",
    floodPps: "Flood PPS",
    format: "格式",
    firewall: "防火墙配置",
    highest: "最高",
    ipBurst: "IP 突发",
    ipPps: "IP PPS",
    interface: "网卡",
    name: "名称",
    node: "节点",
    nodes: "节点",
    page: "页",
    policy: "策略",
    port: "端口",
    priority: "优先级",
    priorityCountries: "国家规则",
    priorityCountriesDetail: "再按国家代码执行允许或拒绝",
    priorityDefense: "动态防御",
    priorityDefenseDetail: "最后执行全局 ip_rate_limit 和 flood",
    priorityOrder: "执行优先级",
    priorityRules: "普通规则 / 威胁情报",
    priorityRulesDetail: "普通规则按数字从小到大匹配；威胁情报编译为拒绝规则",
    priorityWhitelist: "白名单",
    priorityWhitelistDetail: "最高优先级，命中后直接允许",
    protocol: "协议",
    refresh: "刷新",
    rules: "规则",
    rulesHint: "按优先级匹配 CIDR、协议和端口，数字越小优先级越高",
    ruleAction: "规则动作",
    ruleCidr: "规则 CIDR",
    rulePriority: "规则优先级",
    ruleProtocol: "规则协议",
    score: "评分",
    seen: "最后在线",
    seed: "初始化示例策略",
    save: "保存",
    saved: "已保存",
    signIn: "登录",
    status: "状态",
    threats: "威胁",
    threatsHint: "配置威胁情报源，下发为拒绝规则",
    threatScore: "威胁评分",
    threatSourceFormat: "威胁源格式",
    threatSourceName: "威胁源名称",
    threatSourceUrl: "威胁源 URL",
    threatSources: "威胁源",
    trustedCidrs: "白名单",
    trustedCidrsHint: "最高优先级；匹配这些 CIDR 的源 IP 会在普通规则、威胁情报、国家规则、动态防御之前直接允许",
    total: "总数",
    version: "版本",
    nodesHint: "查看各节点最近同步状态"
  },
  en: {
    action: "Action",
    add: "Add",
    allow: "allow",
    apiToken: "API token",
    authInvalid: "missing or invalid API token",
    blockSeconds: "Block seconds",
    burst: "Burst",
    comment: "Comment",
    confirmDelete: "Delete this configuration?",
    countries: "Countries",
    countriesHint: "Allow or deny by country code",
    country: "Country",
    delete: "Delete",
    disabledShort: "off",
    dynamicDefense: "Dynamic Defense",
    dynamicDefenseHint: "Configure global per-source-IP rate limit and flood temporary block",
    deny: "deny",
    emptyCountries: "No country rules",
    emptyNodes: "No node heartbeats",
    emptyRules: "No firewall rules",
    emptyThreats: "No threat sources",
    emptyTrustedCidrs: "No whitelist entries",
    enabled: "Enabled",
    enabledShort: "on",
    error: "Error",
    floodBurst: "Flood burst",
    floodPps: "Flood PPS",
    format: "Format",
    firewall: "Firewall Config",
    highest: "highest",
    ipBurst: "IP burst",
    ipPps: "IP PPS",
    interface: "Interface",
    name: "Name",
    node: "Node",
    nodes: "Nodes",
    page: "Page",
    policy: "Policy",
    port: "Port",
    priority: "Priority",
    priorityCountries: "Country rules",
    priorityCountriesDetail: "Then apply country-code allow or deny decisions",
    priorityDefense: "Dynamic Defense",
    priorityDefenseDetail: "Finally apply global ip_rate_limit and flood",
    priorityOrder: "Enforcement Priority",
    priorityRules: "Firewall Rules / Threat Intel",
    priorityRulesDetail: "Rules match from lower numbers to higher numbers; threat intel is compiled as deny rules",
    priorityWhitelist: "Whitelist",
    priorityWhitelistDetail: "Highest priority; matching sources are allowed immediately",
    protocol: "Protocol",
    refresh: "Refresh",
    rules: "Rules",
    rulesHint: "Match CIDR, protocol, and port by priority; lower numbers have higher priority",
    ruleAction: "Rule action",
    ruleCidr: "Rule CIDR",
    rulePriority: "Rule priority",
    ruleProtocol: "Rule protocol",
    score: "Score",
    seen: "Seen",
    seed: "Seed example policy",
    save: "Save",
    saved: "Saved",
    signIn: "Sign in",
    status: "Status",
    threats: "Threats",
    threatsHint: "Configure threat intelligence feeds as deny rules",
    threatScore: "Threat score",
    threatSourceFormat: "Threat source format",
    threatSourceName: "Threat source name",
    threatSourceUrl: "Threat source URL",
    threatSources: "Threat Sources",
    trustedCidrs: "Whitelist",
    trustedCidrsHint: "Highest priority; source IPs matching these CIDRs are allowed before firewall rules, threat intelligence, country rules, and dynamic defense",
    total: "Total",
    version: "Version",
    nodesHint: "View the last sync state for each node"
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
    positive: (label: string) => `${label} 启用时必须大于 0`,
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
    positive: (label: string) => `${label} must be greater than 0 when enabled`,
    required: (label: string) => `${label} is required`,
    validUrl: (label: string) => `${label} must be a valid URL`
  }
} as const;

type TextKey = keyof typeof messages.zh;
type ValidationKey = keyof typeof validationMessages.zh;

const priorityOrder: { rank: string; label: TextKey; detail: TextKey }[] = [
  { rank: "1", label: "priorityWhitelist", detail: "priorityWhitelistDetail" },
  { rank: "2", label: "priorityRules", detail: "priorityRulesDetail" },
  { rank: "3", label: "priorityCountries", detail: "priorityCountriesDetail" },
  { rank: "4", label: "priorityDefense", detail: "priorityDefenseDetail" }
];

const highestRulePriority = computed(() => {
  if (rules.value.length === 0) {
    return null;
  }
  return Math.min(...rules.value.map((rule) => rule.priority));
});

function isHighestRule(rule: Rule): boolean {
  return highestRulePriority.value !== null && rule.priority === highestRulePriority.value;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  error.value = "";
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const token = currentApiToken();
  if (!token && isProtectedApiPath(path)) {
    authRequired.value = true;
    loginToken.value = apiToken.value;
    loginError.value = t("authInvalid");
    throw new Error(t("authInvalid"));
  }
  if (token) {
    headers.set(authHeader, `Bearer ${token}`);
    headers.set(apiTokenHeader, token);
  }
  debugAuthHeaders(path, headers);
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

function isProtectedApiPath(path: string): boolean {
  const clean = path.replace(/^\/+/, "");
  return (
    clean.startsWith("policy") ||
    clean.startsWith("rules") ||
    clean.startsWith("geo-countries") ||
    clean.startsWith("threat-sources") ||
    clean.startsWith("dynamic-defense") ||
    clean.startsWith("trusted-cidrs") ||
    clean.startsWith("nodes")
  );
}

function debugAuthHeaders(path: string, headers: Headers) {
  const enabled = window.location.hash.includes("debug-auth") || localStorage.getItem("xdp-firewall-debug-auth") === "1";
  if (!enabled || !isProtectedApiPath(path)) {
    return;
  }
  console.info("xdp-firewall auth headers", {
    path,
    authorization: headers.has(authHeader),
    xApiToken: headers.has(apiTokenHeader)
  });
}

function saveApiToken() {
  clearStoredApiToken();
}

function currentApiToken(): string {
  clearStoredApiToken();
  return apiToken.value.trim();
}

function clearApiToken() {
  apiToken.value = "";
  loginToken.value = "";
  clearStoredApiToken();
}

function clearStoredApiToken() {
  localStorage.removeItem("xdp-firewall-api-token");
  sessionStorage.removeItem("xdp-firewall-api-token");
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

function countryLabel(country: CountryOption): string {
  return `${country.code} · ${country.name}`;
}

async function submitLogin() {
  loginError.value = "";
  apiToken.value = loginToken.value.trim();
  clearStoredApiToken();
  authRequired.value = false;
  try {
    await refreshAll();
  } catch (err) {
    authRequired.value = true;
    loginError.value = err instanceof Error ? err.message : String(err);
  }
}

async function refreshAll() {
  loading.value = true;
  try {
    await loadHealth();
    await loadCountries();
    await loadPolicy();
    await loadRules();
    await loadGeo();
    await loadThreats();
    await loadDynamicDefense();
    await loadTrustedCidrs();
    await loadNodes();
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  } finally {
    loading.value = false;
  }
}

async function runAction(action: () => Promise<void>) {
  actionBusy.value = true;
  notice.value = "";
  try {
    await action();
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  } finally {
    actionBusy.value = false;
  }
}

async function loadHealth() {
  const data = await api<{ status: string }>("health");
  health.value = data.status;
}

async function loadPolicy() {
  snapshot.value = await api<Snapshot>("policy");
}

async function loadRules(page = rulePage.page) {
  const data = await api<Page<Rule>>(`rules?${pageQuery(page)}`);
  rules.value = data.items;
  updatePage(rulePage, data);
}

async function loadGeo(page = geoPage.page) {
  const data = await api<Page<GeoCountry>>(`geo-countries?${pageQuery(page)}`);
  geoCountries.value = data.items;
  updatePage(geoPage, data);
}

async function loadThreats(page = threatPage.page) {
  const data = await api<Page<ThreatSource>>(`threat-sources?${pageQuery(page)}`);
  threatSources.value = data.items;
  updatePage(threatPage, data);
}

async function loadDynamicDefense() {
  const data = await api<DynamicDefense>("dynamic-defense");
  Object.assign(dynamicDefense, data);
}

async function loadTrustedCidrs(page = trustedPage.page) {
  const data = await api<Page<TrustedCidr>>(`trusted-cidrs?${pageQuery(page)}`);
  trustedCidrs.value = data.items;
  updatePage(trustedPage, data);
}

async function loadCountries() {
  countries.value = await api<CountryOption[]>("countries");
  if (!countries.value.some((country) => country.code === geoForm.country)) {
    geoForm.country = countries.value[0]?.code ?? "CN";
  }
}

async function loadNodes(page = nodePage.page) {
  const data = await api<Page<NodeState>>(`nodes?${pageQuery(page)}`);
  nodes.value = data.items;
  updatePage(nodePage, data);
}

async function seedExample() {
  await api("policy/seed-example", { method: "POST" });
  await refreshAll();
  showNotice(t("saved"));
}

async function createRule() {
  const payload = validateRuleForm();
  await api("rules", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function createGeo() {
  const payload = validateGeoForm();
  await api("geo-countries", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function createThreat() {
  const payload = validateThreatForm();
  await api("threat-sources", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function saveDynamicDefense() {
  const payload = validateDynamicDefense();
  await api("dynamic-defense", {
    method: "PUT",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function createTrustedCidr() {
  const payload = validateTrustedCidrForm();
  await api("trusted-cidrs", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function deleteItem(path: string) {
  if (!window.confirm(t("confirmDelete"))) {
    return;
  }
  await api(path, { method: "DELETE" });
  await refreshAll();
  showNotice(t("saved"));
}

function showNotice(message: string) {
  notice.value = message;
  window.setTimeout(() => {
    if (notice.value === message) {
      notice.value = "";
    }
  }, 2800);
}

onMounted(() => {
  clearStoredApiToken();
  syncTabFromHash();
  window.addEventListener("hashchange", syncTabFromHash);
  window.addEventListener("pagehide", clearApiToken);
  window.addEventListener("beforeunload", clearApiToken);
  document.addEventListener("visibilitychange", clearApiTokenOnHidden);
  void refreshAll();
});

onBeforeUnmount(() => {
  clearApiToken();
  window.removeEventListener("hashchange", syncTabFromHash);
  window.removeEventListener("pagehide", clearApiToken);
  window.removeEventListener("beforeunload", clearApiToken);
  document.removeEventListener("visibilitychange", clearApiTokenOnHidden);
});

watch(apiToken, saveApiToken);

function clearApiTokenOnHidden() {
  if (document.visibilityState === "hidden") {
    clearApiToken();
  }
}

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

function validateGeoForm() {
  return {
    country: requireCountry(geoForm.country),
    action: requireOneOf(t("country"), geoForm.action, actions)
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

function validateDynamicDefense() {
  const payload = {
    enabled: dynamicDefense.enabled,
    ip_rate_limit_enabled: dynamicDefense.ip_rate_limit_enabled,
    ip_packets_per_second: optionalNonNegativeInteger(t("ipPps"), dynamicDefense.ip_packets_per_second),
    ip_burst: optionalNonNegativeInteger(t("ipBurst"), dynamicDefense.ip_burst),
    flood_enabled: dynamicDefense.flood_enabled,
    flood_packets_per_second: optionalNonNegativeInteger(t("floodPps"), dynamicDefense.flood_packets_per_second),
    flood_burst: optionalNonNegativeInteger(t("floodBurst"), dynamicDefense.flood_burst),
    flood_block_seconds: optionalNonNegativeInteger(t("blockSeconds"), dynamicDefense.flood_block_seconds)
  };
  if (payload.enabled && payload.ip_rate_limit_enabled) {
    requirePositive(t("ipPps"), payload.ip_packets_per_second);
    requirePositive(t("ipBurst"), payload.ip_burst);
  }
  if (payload.enabled && payload.flood_enabled) {
    requirePositive(t("floodPps"), payload.flood_packets_per_second);
    requirePositive(t("floodBurst"), payload.flood_burst);
    requirePositive(t("blockSeconds"), payload.flood_block_seconds);
  }
  return payload;
}

function validateTrustedCidrForm() {
  return {
    cidr: requireCidr("CIDR", trustedForm.cidr),
    comment: String(trustedForm.comment ?? "").trim() || null
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

function requirePositive(label: string, value: number | null) {
  if (value === null || value <= 0) {
    throwValidation(v("positive", label));
  }
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

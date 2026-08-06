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
            <Button variant="secondary" :title="t('refresh')" :disabled="actionBusy" @click="runAction(refreshCurrentView)">
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
          <strong>{{ loadedTabs.has("rules") ? rulePage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("countries") }}</span>
          <strong>{{ loadedTabs.has("geo") ? geoPage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("tempBans") }}</span>
          <strong>{{ loadedTabs.has("tempBans") ? tempBanPage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("threatSources") }}</span>
          <strong>{{ loadedTabs.has("threats") ? threatPage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("dynamicDefense") }}</span>
          <strong>{{ loadedTabs.has("defense") ? (dynamicDefense.enabled ? t("enabledShort") : t("disabledShort")) : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("customRateLimits") }}</span>
          <strong>{{ loadedTabs.has("defense") ? dynamicRatePage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("trustedCidrs") }}</span>
          <strong>{{ loadedTabs.has("trusted") ? trustedPage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("nodes") }}</span>
          <strong>{{ loadedTabs.has("nodes") ? nodePage.total : "-" }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("dropEvents") }}</span>
          <strong>{{ dropEvents.length }}</strong>
        </div>
      </div>

      <section v-if="tab === 'rules'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("rules") }}</h2>
            <p>{{ t("rulesHint") }}</p>
          </div>
        </div>
        <div class="form-grid rule-form">
          <label class="field">
            <span>{{ t("ruleKey") }}</span>
            <Input v-model="ruleForm.rule_key" aria-label="Rule key" placeholder="edge-web-deny" />
          </label>
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
            <Input
              v-model="ruleForm.cidr"
              aria-label="CIDR"
              placeholder="203.0.113.0/24"
              :aria-invalid="Boolean(fieldErrors.ruleCidr)"
              @blur="validateField('ruleCidr')"
              @input="validateTouchedField('ruleCidr')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.ruleCidr) }">{{ fieldErrors.ruleCidr }}</small>
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="ruleForm.protocol" aria-label="Protocol" @change="validateFieldAfterUpdate('rulePort')">
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input
              v-model="ruleForm.port"
              type="number"
              min="1"
              max="65535"
              aria-label="Port"
              placeholder="80"
              :aria-invalid="Boolean(fieldErrors.rulePort)"
              @blur="validateField('rulePort')"
              @input="validateFieldAfterUpdate('rulePort')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.rulePort) }">{{ fieldErrors.rulePort }}</small>
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy || hasFieldErrors(ruleErrorFields)" @click="runAction(createRule)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid rule-filter-form">
          <label class="field">
            <span>{{ t("ruleKey") }}</span>
            <Input v-model="ruleFilters.rule_key" aria-label="Rule key filter" placeholder="edge-web-deny" />
          </label>
          <label class="field">
            <span>{{ t("action") }}</span>
            <Select v-model="ruleFilters.action" aria-label="Rule action filter">
              <option value="all">{{ t("allActions") }}</option>
              <option value="deny">{{ t("deny") }}</option>
              <option value="allow">{{ t("allow") }}</option>
            </Select>
          </label>
          <label class="field">
            <span>CIDR</span>
            <Input v-model="ruleFilters.cidr" aria-label="Rule CIDR filter" placeholder="203.0.113.0/24" />
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="ruleFilters.protocol" aria-label="Rule protocol filter">
              <option value="all">{{ t("allProtocols") }}</option>
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input v-model="ruleFilters.port" type="number" min="1" max="65535" aria-label="Rule port filter" placeholder="443" />
          </label>
          <label class="field">
            <span>{{ t("priority") }}</span>
            <Input v-model="ruleFilters.priority" type="number" aria-label="Rule priority filter" placeholder="10" />
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryRules)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasRuleFilters" :title="t('clear')" @click="runAction(clearRuleFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("ruleKey") }}</th>
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
              <td colspan="7" class="empty">{{ t("emptyRules") }}</td>
            </tr>
            <tr v-for="rule in rules" :key="rule.id">
              <td>{{ rule.rule_key ?? "-" }}</td>
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
          <Button variant="secondary" :title="t('refreshCountryIps')" :disabled="actionBusy" @click="runAction(refreshGeoCountries)">
            <RefreshCcw :class="{ spin: loading }" :size="16" />
          </Button>
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
        <div class="subsection-head compact-section">
          <div>
            <h3>{{ t("countryLookup") }}</h3>
            <p>{{ t("countryLookupHint") }}</p>
          </div>
        </div>
        <div class="form-grid geo-lookup-form">
          <label class="field">
            <span>{{ t("ipAddress") }}</span>
            <Input
              v-model="geoLookupForm.ip"
              aria-label="Geo lookup IP"
              placeholder="8.8.8.8"
              :aria-invalid="Boolean(fieldErrors.geoLookupIp)"
              @blur="validateField('geoLookupIp')"
              @input="validateTouchedField('geoLookupIp')"
              @keyup.enter="runAction(lookupGeoIp)"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.geoLookupIp) }">{{ fieldErrors.geoLookupIp }}</small>
          </label>
          <Button class="form-submit" :title="t('query')" :disabled="actionBusy || hasFieldErrors(geoLookupErrorFields)" @click="runAction(lookupGeoIp)">
            <Globe2 :size="16" />
          </Button>
          <div class="lookup-result">
            <span>{{ t("country") }}</span>
            <strong>{{ geoLookupResult ? geoLookupLabel : '-' }}</strong>
          </div>
        </div>
        <div class="form-grid geo-filter-form">
          <label class="field">
            <span>{{ t("country") }}</span>
            <Select v-model="geoFilters.country" aria-label="Country filter">
              <option value="all">{{ t("allCountries") }}</option>
              <option v-for="country in countries" :key="country.code" :value="country.code">{{ countryLabel(country) }}</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("action") }}</span>
            <Select v-model="geoFilters.action" aria-label="Country action filter">
              <option value="all">{{ t("allActions") }}</option>
              <option value="allow">{{ t("allow") }}</option>
              <option value="deny">{{ t("deny") }}</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("status") }}</span>
            <Select v-model="geoFilters.enabled" aria-label="Country status filter">
              <option value="all">{{ t("allStatuses") }}</option>
              <option value="true">{{ t("enabled") }}</option>
              <option value="false">{{ t("disabledShort") }}</option>
            </Select>
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryGeo)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasGeoFilters" :title="t('clear')" @click="runAction(clearGeoFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
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

      <section v-if="tab === 'tempBans'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("tempBans") }}</h2>
            <p>{{ t("tempBansHint") }}</p>
          </div>
        </div>
        <div class="form-grid temp-ban-form">
          <label class="field">
            <span>{{ t("sourceIp") }}</span>
            <Input
              v-model="tempBanForm.ip"
              aria-label="Temporary ban source IP"
              placeholder="203.0.113.10"
              :aria-invalid="Boolean(fieldErrors.tempBanIp)"
              @blur="validateField('tempBanIp')"
              @input="validateTouchedField('tempBanIp')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.tempBanIp) }">{{ fieldErrors.tempBanIp }}</small>
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="tempBanForm.protocol" aria-label="Temporary ban protocol" @change="validateFieldAfterUpdate('tempBanPort')">
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input
              v-model="tempBanForm.port"
              type="number"
              min="1"
              max="65535"
              aria-label="Temporary ban port"
              placeholder="443"
              :aria-invalid="Boolean(fieldErrors.tempBanPort)"
              @blur="validateField('tempBanPort')"
              @input="validateFieldAfterUpdate('tempBanPort')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.tempBanPort) }">{{ fieldErrors.tempBanPort }}</small>
          </label>
          <label class="field">
            <span>{{ t("durationSeconds") }}</span>
            <Input v-model.number="tempBanForm.duration_seconds" type="number" aria-label="Temporary ban duration seconds" />
          </label>
          <label class="field">
            <span>{{ t("comment") }}</span>
            <Input v-model="tempBanForm.comment" aria-label="Temporary ban comment" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy || hasFieldErrors(tempBanErrorFields)" @click="runAction(createTempBan)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid temp-ban-filter-form">
          <label class="field">
            <span>{{ t("sourceIp") }}</span>
            <Input v-model="tempBanFilters.ip" aria-label="Temporary ban source IP filter" placeholder="203.0.113.10" />
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="tempBanFilters.protocol" aria-label="Temporary ban protocol filter">
              <option value="all">{{ t("allProtocols") }}</option>
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input v-model="tempBanFilters.port" type="number" min="1" max="65535" aria-label="Temporary ban port filter" placeholder="443" />
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryTempBans)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasTempBanFilters" :title="t('clear')" @click="runAction(clearTempBanFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("sourceIp") }}</th>
              <th>{{ t("protocol") }}</th>
              <th>{{ t("port") }}</th>
              <th>{{ t("expiresAt") }}</th>
              <th>{{ t("comment") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!loading && tempBans.length === 0">
              <td colspan="6" class="empty">{{ t("emptyTempBans") }}</td>
            </tr>
            <tr v-for="ban in tempBans" :key="ban.id">
              <td>{{ ban.ip }}</td>
              <td>{{ ban.protocol }}</td>
              <td>{{ ban.port ?? '*' }}</td>
              <td>{{ formatLocalTime(ban.expires_at) }}</td>
              <td class="clip">{{ ban.comment ?? '' }}</td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/temp-bans/${ban.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="tempBanPage.page <= 1" @click="runAction(() => loadTempBans(tempBanPage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(tempBanPage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(tempBanPage)" @click="runAction(() => loadTempBans(tempBanPage.page + 1))"><ChevronRight :size="15" /></Button>
        </div>
      </section>

      <section v-if="tab === 'threats'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("threatSources") }}</h2>
            <p>{{ t("threatsHint") }}</p>
          </div>
          <Button variant="secondary" :title="t('refreshThreatFeeds')" :disabled="actionBusy" @click="runAction(refreshThreatSources)">
            <RefreshCcw :class="{ spin: loading }" :size="16" />
          </Button>
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
              <option value="voipbl">voipbl</option>
              <option value="spamhaus_drop">spamhaus_drop</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("score") }}</span>
            <Input v-model.number="threatForm.min_score" type="number" aria-label="Score" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy" @click="runAction(createThreat)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid threat-filter-form">
          <label class="field">
            <span>{{ t("name") }}</span>
            <Input v-model="threatFilters.name" aria-label="Threat source name filter" placeholder="ipsum" />
          </label>
          <label class="field">
            <span>URL</span>
            <Input v-model="threatFilters.url" aria-label="Threat source URL filter" placeholder="https://..." />
          </label>
          <label class="field">
            <span>{{ t("format") }}</span>
            <Select v-model="threatFilters.format" aria-label="Threat source format filter">
              <option value="all">{{ t("allFormats") }}</option>
              <option value="cidr">cidr</option>
              <option value="ips">ips</option>
              <option value="ipsum">ipsum</option>
              <option value="voipbl">voipbl</option>
              <option value="spamhaus_drop">spamhaus_drop</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("status") }}</span>
            <Select v-model="threatFilters.enabled" aria-label="Threat source status filter">
              <option value="all">{{ t("allStatuses") }}</option>
              <option value="true">{{ t("enabled") }}</option>
              <option value="false">{{ t("disabledShort") }}</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("score") }}</span>
            <Input v-model="threatFilters.min_score" type="number" min="0" aria-label="Threat source score filter" placeholder="3" />
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryThreats)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasThreatFilters" :title="t('clear')" @click="runAction(clearThreatFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
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
          <label class="header-toggle">
            <input v-model="dynamicDefense.enabled" type="checkbox" />
            <span>{{ dynamicDefense.enabled ? t("enabledShort") : t("disabledShort") }}</span>
          </label>
        </div>
        <div class="form-grid defense-form">
          <div class="defense-row">
            <label class="check-field defense-toggle">
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
          </div>
          <div class="defense-row">
            <label class="check-field defense-toggle">
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
          </div>
          <Button class="form-submit" :title="t('save')" :disabled="actionBusy" @click="runAction(saveDynamicDefense)"><DatabaseZap :size="16" /></Button>
        </div>
        <div class="subsection-head">
          <div>
            <h3>{{ t("customRateLimits") }}</h3>
            <p>{{ t("customRateLimitsHint") }}</p>
          </div>
        </div>
        <div class="form-grid custom-rate-form">
          <label class="field">
            <span>{{ t("priority") }}</span>
            <Input v-model.number="dynamicRateForm.priority" type="number" aria-label="Dynamic rate priority" />
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="dynamicRateForm.protocol" aria-label="Dynamic rate protocol" @change="validateFieldAfterUpdate('dynamicRatePort')">
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input
              v-model="dynamicRateForm.port"
              type="number"
              min="1"
              max="65535"
              aria-label="Dynamic rate port"
              placeholder="443"
              :aria-invalid="Boolean(fieldErrors.dynamicRatePort)"
              @blur="validateField('dynamicRatePort')"
              @input="validateFieldAfterUpdate('dynamicRatePort')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.dynamicRatePort) }">{{ fieldErrors.dynamicRatePort }}</small>
          </label>
          <label class="field">
            <span>PPS</span>
            <Input v-model.number="dynamicRateForm.packets_per_second" type="number" aria-label="Dynamic rate PPS" />
          </label>
          <label class="field">
            <span>{{ t("burst") }}</span>
            <Input v-model.number="dynamicRateForm.burst" type="number" aria-label="Dynamic rate burst" />
          </label>
          <label class="field">
            <span>{{ t("comment") }}</span>
            <Input v-model="dynamicRateForm.comment" aria-label="Dynamic rate comment" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy || hasFieldErrors(dynamicRateErrorFields)" @click="runAction(createDynamicRateLimit)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid custom-rate-filter-form">
          <label class="field">
            <span>{{ t("priority") }}</span>
            <Input v-model="dynamicRateFilters.priority" type="number" aria-label="Dynamic rate priority filter" placeholder="10" />
          </label>
          <label class="field">
            <span>{{ t("protocol") }}</span>
            <Select v-model="dynamicRateFilters.protocol" aria-label="Dynamic rate protocol filter">
              <option value="all">{{ t("allProtocols") }}</option>
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </label>
          <label class="field">
            <span>{{ t("port") }}</span>
            <Input v-model="dynamicRateFilters.port" type="number" min="1" max="65535" aria-label="Dynamic rate port filter" placeholder="443" />
          </label>
          <label class="field">
            <span>PPS</span>
            <Input v-model="dynamicRateFilters.packets_per_second" type="number" min="1" aria-label="Dynamic rate PPS filter" placeholder="1000" />
          </label>
          <label class="field">
            <span>{{ t("burst") }}</span>
            <Input v-model="dynamicRateFilters.burst" type="number" min="1" aria-label="Dynamic rate burst filter" placeholder="2000" />
          </label>
          <label class="field">
            <span>{{ t("status") }}</span>
            <Select v-model="dynamicRateFilters.enabled" aria-label="Dynamic rate status filter">
              <option value="all">{{ t("allStatuses") }}</option>
              <option value="true">{{ t("enabled") }}</option>
              <option value="false">{{ t("disabledShort") }}</option>
            </Select>
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryDynamicRateLimits)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasDynamicRateFilters" :title="t('clear')" @click="runAction(clearDynamicRateFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("priority") }}</th>
              <th>{{ t("protocol") }}</th>
              <th>{{ t("port") }}</th>
              <th>PPS</th>
              <th>{{ t("burst") }}</th>
              <th>{{ t("comment") }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="!loading && dynamicRateLimits.length === 0">
              <td colspan="7" class="empty">{{ t("emptyCustomRateLimits") }}</td>
            </tr>
            <tr v-for="limit in dynamicRateLimits" :key="limit.id">
              <td>
                <div class="priority-cell">
                  <span>{{ limit.priority }}</span>
                  <Badge v-if="isHighestDynamicRateLimit(limit)" tone="amber">{{ t("highest") }}</Badge>
                </div>
              </td>
              <td>{{ limit.protocol }}</td>
              <td>{{ limit.port ?? '*' }}</td>
              <td>{{ limit.packets_per_second }}</td>
              <td>{{ limit.burst }}</td>
              <td class="clip">{{ limit.comment ?? '' }}</td>
              <td class="right"><Button variant="ghost" :title="t('delete')" :disabled="actionBusy" @click="runAction(() => deleteItem(`/dynamic-rate-limits/${limit.id}`))"><Trash2 :size="15" /></Button></td>
            </tr>
          </tbody>
        </table>
        <div class="pager">
          <Button variant="secondary" :disabled="dynamicRatePage.page <= 1" @click="runAction(() => loadDynamicRateLimits(dynamicRatePage.page - 1))"><ChevronLeft :size="15" /></Button>
          <span>{{ pageLabel(dynamicRatePage) }}</span>
          <Button variant="secondary" :disabled="!hasNext(dynamicRatePage)" @click="runAction(() => loadDynamicRateLimits(dynamicRatePage.page + 1))"><ChevronRight :size="15" /></Button>
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
            <Input
              v-model="trustedForm.cidr"
              aria-label="Trusted CIDR"
              placeholder="10.0.0.0/8"
              :aria-invalid="Boolean(fieldErrors.trustedCidr)"
              @blur="validateField('trustedCidr')"
              @input="validateTouchedField('trustedCidr')"
            />
            <small class="field-error" :class="{ visible: Boolean(fieldErrors.trustedCidr) }">{{ fieldErrors.trustedCidr }}</small>
          </label>
          <label class="field">
            <span>{{ t("comment") }}</span>
            <Input v-model="trustedForm.comment" aria-label="Comment" />
          </label>
          <Button class="form-submit" :title="t('add')" :disabled="actionBusy || hasFieldErrors(trustedErrorFields)" @click="runAction(createTrustedCidr)"><Plus :size="16" /></Button>
        </div>
        <div class="form-grid trusted-filter-form">
          <label class="field">
            <span>CIDR</span>
            <Input v-model="trustedFilters.cidr" aria-label="Trusted CIDR filter" placeholder="10.0.0.0/8" />
          </label>
          <label class="field">
            <span>{{ t("status") }}</span>
            <Select v-model="trustedFilters.enabled" aria-label="Trusted CIDR status filter">
              <option value="all">{{ t("allStatuses") }}</option>
              <option value="true">{{ t("enabled") }}</option>
              <option value="false">{{ t("disabledShort") }}</option>
            </Select>
          </label>
          <div class="filter-actions">
            <Button :disabled="actionBusy" :title="t('query')" @click="runAction(queryTrustedCidrs)"><Search :size="15" /><span>{{ t("query") }}</span></Button>
            <Button variant="secondary" :disabled="actionBusy || !hasTrustedFilters" :title="t('clear')" @click="runAction(clearTrustedFilters)"><X :size="15" /><span>{{ t("clear") }}</span></Button>
          </div>
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
              <td>{{ formatLocalTime(node.last_seen_at) }}</td>
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

      <section v-if="tab === 'drops'" class="panel">
        <div class="panel-head">
          <div>
            <h2>{{ t("dropEvents") }}</h2>
            <p>{{ t("dropEventsHint") }}</p>
          </div>
          <div class="panel-actions">
            <Button v-if="!dropStreaming" :disabled="actionBusy" @click="startDropStream">
              <Activity :size="16" />
              <span>{{ t("start") }}</span>
            </Button>
            <Button v-else variant="secondary" @click="stopDropStream">
              <Square :size="16" />
              <span>{{ t("stop") }}</span>
            </Button>
            <Button variant="ghost" :title="t('clear')" @click="clearDropEvents"><Trash2 :size="15" /></Button>
          </div>
        </div>
        <div class="drop-status">
          <Badge :tone="dropStreaming ? 'green' : 'amber'">{{ dropStreaming ? t("streaming") : t("stopped") }}</Badge>
          <label class="inline-select">
            <span>{{ t("dropScope") }}</span>
            <Select v-model="dropNodeFilter" :disabled="dropStreaming" aria-label="Drop node filter">
              <option value="all">{{ t("allNodes") }}</option>
              <option v-for="node in nodes" :key="node.node_id" :value="node.node_id">{{ node.node_id }}</option>
            </Select>
          </label>
          <label class="inline-select">
            <span>{{ t("sourceIp") }}</span>
            <Input v-model="dropFilters.src" class="compact-input" aria-label="Drop source IP filter" placeholder="203.0.113.10" />
          </label>
          <label class="inline-select">
            <span>{{ t("protocol") }}</span>
            <Select v-model="dropFilters.proto" aria-label="Drop protocol filter">
              <option value="all">{{ t("allProtocols") }}</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="any">any</option>
            </Select>
          </label>
          <label class="inline-select">
            <span>{{ t("port") }}</span>
            <Input v-model="dropFilters.port" class="compact-input port-filter-input" aria-label="Drop port filter" placeholder="443" />
          </label>
          <span>{{ t("dropEventsLimit") }}</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>{{ t("seen") }}</th>
              <th>{{ t("node") }}</th>
              <th>{{ t("reason") }}</th>
              <th>{{ t("sourceIp") }}</th>
              <th>{{ t("threatSource") }}</th>
              <th>{{ t("protocol") }}</th>
              <th>{{ t("port") }}</th>
              <th>{{ t("country") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="filteredDropEvents.length === 0">
              <td colspan="8" class="empty">{{ t("emptyDropEvents") }}</td>
            </tr>
            <tr v-for="event in filteredDropEvents" :key="event.local_id">
              <td>{{ formatLocalTime(event.time) }}</td>
              <td class="clip">{{ event.node_id }}</td>
              <td><Badge :tone="dropReasonTone(event.reason)">{{ dropReasonLabel(event.reason) }}</Badge></td>
              <td>{{ event.src }}</td>
              <td>{{ event.threat_source || '-' }}</td>
              <td>{{ event.proto }}</td>
              <td>{{ event.dport || '*' }}</td>
              <td>{{ event.country || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <div v-if="loading" class="loading-bar"><span></span></div>
      <p v-if="error" class="error">{{ error }}</p>
      <p v-else-if="notice" class="notice">{{ notice }}</p>
    </main>

    <button
      class="help-fab"
      :class="{ dragging: helpFabDragging }"
      :style="helpFabStyle"
      :aria-label="t('help')"
      :title="t('help')"
      @click="openHelpFromFab"
      @pointerdown="startHelpFabDrag"
      @pointermove="moveHelpFab"
      @pointerup="endHelpFabDrag"
      @pointercancel="endHelpFabDrag"
    >
      <BookOpen :size="20" />
    </button>

    <div v-if="helpOpen" class="help-overlay" @click.self="helpOpen = false">
      <aside class="help-drawer" role="dialog" aria-modal="true" :aria-label="t('help')">
        <div class="help-head">
          <div>
            <h2>{{ t("help") }}</h2>
            <p>{{ t("helpHint") }}</p>
          </div>
          <Button variant="ghost" :title="t('close')" @click="helpOpen = false">
            <X :size="15" />
          </Button>
        </div>
        <div class="help-body">
          <section class="doc-block">
            <h3>{{ t("priorityOrder") }}</h3>
            <div class="priority-list">
              <article v-for="item in priorityOrder" :key="item.rank" class="priority-row">
                <strong>{{ item.rank }}</strong>
                <div>
                  <span>{{ t(item.label) }}</span>
                  <small>{{ t(item.detail) }}</small>
                </div>
              </article>
            </div>
          </section>
          <section class="doc-block">
            <h3>{{ t("apiDocs") }}</h3>
            <p>{{ t("apiDocsHint") }}</p>
          </section>
          <section class="doc-block">
            <h3>{{ t("apiAuth") }}</h3>
            <p>{{ t("apiAuthText") }}</p>
            <pre><code>Authorization: Bearer &lt;token&gt;
X-API-Token: &lt;token&gt;</code></pre>
          </section>
          <section class="doc-block">
            <h3>{{ t("apiPagination") }}</h3>
            <p>{{ t("apiPaginationText") }}</p>
            <pre><code>{{ pageResponseExample }}</code></pre>
          </section>
          <section v-for="section in apiDocSections" :key="section.title" class="doc-block">
            <h3>{{ section.title }}</h3>
            <p>{{ section.description }}</p>
            <div class="endpoint-list">
              <article v-for="endpoint in section.endpoints" :key="`${endpoint.method}-${endpoint.path}`" class="endpoint-row">
                <div class="endpoint-main">
                  <Badge :tone="methodTone(endpoint.method)">{{ endpoint.method }}</Badge>
                  <code>{{ endpoint.path }}</code>
                  <span>{{ endpoint.summary }}</span>
                </div>
                <pre v-if="endpoint.body"><code>{{ endpoint.body }}</code></pre>
                <pre v-if="endpoint.curl"><code>{{ endpoint.curl }}</code></pre>
              </article>
            </div>
          </section>
        </div>
      </aside>
    </div>

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
import { Activity, Ban, BookOpen, ChevronLeft, ChevronRight, DatabaseZap, Globe2, KeyRound, ListFilter, Plus, RefreshCcw, Search, Server, ShieldCheck, Square, Trash2, X } from "lucide-vue-next";
import Badge from "./components/ui/Badge.vue";
import Button from "./components/ui/Button.vue";
import Input from "./components/ui/Input.vue";
import Select from "./components/ui/Select.vue";

type Rule = { id: number; rule_key?: string | null; priority: number; action: string; cidr: string; protocol?: string | null; port?: number | null };
type GeoCountry = { id: number; country: string; action: string; packets_per_second?: number; burst?: number };
type ThreatSource = { id: number; name: string; url: string; format: string; min_score?: number };
type TrustedCidr = { id: number; cidr: string; enabled: boolean; comment?: string };
type DynamicRateLimit = { id: number; enabled: boolean; priority: number; protocol: string; port?: number | null; packets_per_second: number; burst: number; comment?: string | null };
type TempBan = { id: number; ip: string; protocol: string; port?: number | null; expires_at: string; comment?: string | null; created_at: string };
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
type DropEvent = { local_id: number; node_id: string; interface_name: string; time: string; event_time_ns: number; cpu: number; reason: string; src: string; family: number; proto: string; dport: number; country?: string; threat_source?: string; action: string };
type Snapshot = { version: number };
type Page<T> = { items: T[]; total: number; page: number; page_size: number; total_pages: number };
type PageState = { page: number; total_pages: number; total: number };
type ApiDocEndpoint = { method: string; path: string; summary: string; body?: string; curl?: string };
type ApiDocSection = { title: string; description: string; endpoints: ApiDocEndpoint[] };
type GeoRefreshResponse = { countries: string[]; checked_country_count: number; changed_country_count: number; prefix_count: number; provider_base_url: string; refresh_status?: string; cached?: boolean; running?: boolean };
type ThreatRefreshResponse = { enabled_source_count: number; changed_source_count: number; prefix_count: number; refreshed: boolean; refresh_status?: string; cached?: boolean; running?: boolean };
type GeoLookupResponse = { ip: string; country?: string | null; country_name?: string | null };
type Lang = "zh" | "en";
type FieldKey = "ruleCidr" | "rulePort" | "geoLookupIp" | "tempBanIp" | "tempBanPort" | "dynamicRatePort" | "trustedCidr";
const ruleErrorFields: FieldKey[] = ["ruleCidr", "rulePort"];
const geoLookupErrorFields: FieldKey[] = ["geoLookupIp"];
const tempBanErrorFields: FieldKey[] = ["tempBanIp", "tempBanPort"];
const dynamicRateErrorFields: FieldKey[] = ["dynamicRatePort"];
const trustedErrorFields: FieldKey[] = ["trustedCidr"];

const tabs = [
  { id: "trusted", label: "trustedCidrs", icon: KeyRound },
  { id: "tempBans", label: "tempBans", icon: Ban },
  { id: "rules", label: "rules", icon: ListFilter },
  { id: "threats", label: "threats", icon: ShieldCheck },
  { id: "geo", label: "countries", icon: Globe2 },
  { id: "defense", label: "dynamicDefense", icon: ShieldCheck },
  { id: "drops", label: "dropEvents", icon: Activity },
  { id: "nodes", label: "nodes", icon: Server }
] as const;

const tab = ref<(typeof tabs)[number]["id"]>("rules");
const loadedTabs = reactive(new Set<string>());
const pendingTabLoads = new Map<string, Promise<void>>();
const helpOpen = ref(false);
const helpFabDragging = ref(false);
const helpFabMoved = ref(false);
const helpFabPosition = reactive<{ left: number | null; top: number | null }>({ left: null, top: null });
let helpFabStart = { x: 0, y: 0, left: 0, top: 0 };
const language = ref<Lang>(localStorage.getItem("xdp-firewall-language") === "en" ? "en" : "zh");
const health = ref("loading");
const error = ref("");
const notice = ref("");
const fieldErrors = reactive<Partial<Record<FieldKey, string>>>({});
const touchedFields = reactive<Partial<Record<FieldKey, boolean>>>({});
const loading = ref(false);
const actionBusy = ref(false);
const apiToken = ref(sessionStorage.getItem("xdp-firewall-api-token") ?? "");
const loginToken = ref(apiToken.value);
const loginError = ref("");
const authRequired = ref(false);
const snapshot = ref<Snapshot | null>(null);
const rules = ref<Rule[]>([]);
const geoCountries = ref<GeoCountry[]>([]);
const threatSources = ref<ThreatSource[]>([]);
const trustedCidrs = ref<TrustedCidr[]>([]);
const dynamicRateLimits = ref<DynamicRateLimit[]>([]);
const tempBans = ref<TempBan[]>([]);
const countries = ref<CountryOption[]>([]);
const nodes = ref<NodeState[]>([]);
const dropEvents = ref<DropEvent[]>([]);
const dropStreaming = ref(false);
const dropNodeFilter = ref("all");
const dropFilters = reactive({ src: "", proto: "all", port: "" });
let dropAbort: AbortController | null = null;
let dropEventSeq = 0;
const rulePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const geoPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const threatPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const trustedPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const dynamicRatePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const tempBanPage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });
const nodePage = reactive<PageState>({ page: 1, total_pages: 0, total: 0 });

const ruleForm = reactive({ rule_key: "", priority: 10, action: "deny", cidr: "203.0.113.0/24", protocol: "any", port: "" });
const ruleFilters = reactive({ rule_key: "", action: "all", cidr: "", protocol: "all", port: "", priority: "" });
const geoForm = reactive({ country: "CN", action: "allow" });
const geoFilters = reactive({ country: "all", action: "all", enabled: "all" });
const geoLookupForm = reactive({ ip: "8.8.8.8" });
const geoLookupResult = ref<GeoLookupResponse | null>(null);
const threatForm = reactive({ name: "ipsum", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", format: "ipsum", min_score: 3 });
const threatFilters = reactive({ name: "", url: "", format: "all", enabled: "all", min_score: "" });
const trustedForm = reactive({ cidr: "10.0.0.0/8", comment: "" });
const trustedFilters = reactive({ cidr: "", enabled: "all" });
const dynamicRateForm = reactive({ priority: 10, protocol: "tcp", port: "443", packets_per_second: 1000, burst: 2000, comment: "" });
const dynamicRateFilters = reactive({ priority: "", protocol: "all", port: "", packets_per_second: "", burst: "", enabled: "all" });
const tempBanForm = reactive({ ip: "203.0.113.10", protocol: "any", port: "", duration_seconds: 300, comment: "" });
const tempBanFilters = reactive({ ip: "", protocol: "all", port: "" });
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
const threatFormats = new Set(["cidr", "ips", "ipsum", "voipbl", "spamhaus_drop"]);
const pageSize = 20;
const authHeader = "Authorization";
const apiTokenHeader = "X-API-Token";

const messages = {
  zh: {
    action: "动作",
    add: "添加",
    allow: "允许",
    apiToken: "API 令牌",
    apiAuth: "鉴权",
    apiAuthText: "除 /health、/countries 和前端静态资源外，配置、节点和 Drop 订阅接口都需要 API 令牌。两种请求头都支持。",
    apiDocs: "API 文档",
    apiDocsHint: "查看控制面 HTTP API 的请求方式、参数和示例",
    apiPagination: "分页",
    apiPaginationText: "列表接口支持 page 和 page_size，默认 page_size 为 20，最大 500。",
    allNodes: "全部节点",
    allActions: "全部动作",
    allCountries: "全部国家",
    allFormats: "全部格式",
    allProtocols: "全部协议",
    allStatuses: "全部状态",
    authInvalid: "API 令牌缺失或无效",
    blockSeconds: "封禁秒数",
    burst: "突发",
    close: "关闭",
    comment: "备注",
    confirmDelete: "确认删除这条配置？",
    countries: "国家",
    countriesHint: "按国家代码配置允许或拒绝",
    country: "国家",
    countryLookup: "IP 归属查询",
    countryLookupHint: "使用控制面内存 MMDB 查询源 IP 所属国家",
    customRateLimits: "自定义限流",
    customRateLimitsHint: "按协议或目的端口配置限流；优先级高于全局 IP 限流和 Flood",
    delete: "删除",
    disabledShort: "关",
    clear: "清空",
    dropEvents: "实时 Drop",
    dropEventsHint: "通过 xDS 从 agent 订阅实时丢包事件",
    dropEventsLimit: "仅保留最近 300 条",
    dropScope: "订阅范围",
    durationSeconds: "时长秒数",
    dynamicDefense: "动态防御",
    dynamicDefenseHint: "配置全局每源 IP 限流和 flood 临时封禁",
    deny: "拒绝",
    emptyCountries: "暂无国家规则",
    emptyNodes: "暂无节点心跳",
    emptyRules: "暂无普通防火墙规则",
    emptyThreats: "暂无威胁源",
    emptyTrustedCidrs: "暂无白名单",
    emptyDropEvents: "暂无 Drop 事件",
    emptyCustomRateLimits: "暂无自定义限流",
    emptyTempBans: "暂无临时封禁",
    enabled: "启用",
    enabledShort: "开",
    error: "错误",
    expiresAt: "到期时间",
    floodBurst: "Flood 突发",
    floodPps: "Flood PPS",
    format: "格式",
    firewall: "防火墙配置",
    help: "帮助",
    helpHint: "执行优先级和 API 使用说明",
    highest: "最高",
    ipBurst: "IP 突发",
    ipAddress: "IP 地址",
    ipPps: "IP PPS",
    interface: "网卡",
    name: "名称",
    node: "节点",
    nodes: "节点",
    page: "页",
    policy: "策略",
    port: "端口",
    priority: "优先级",
    ruleKey: "规则键",
    priorityCountries: "国家规则",
    priorityCountriesDetail: "再按国家代码执行允许或拒绝",
    priorityTempBans: "临时封禁",
    priorityTempBansDetail: "白名单之后立即拒绝命中的临时封禁",
    priorityDefenseCustom: "自定义限流",
    priorityDefenseCustomDetail: "先按协议或目的端口执行动态防御限流",
    priorityDefense: "全局动态防御",
    priorityDefenseDetail: "最后执行全局 ip_rate_limit 和 flood",
    priorityOrder: "执行优先级",
    priorityRules: "普通规则 / 威胁情报",
    priorityRulesDetail: "普通规则按数字从小到大匹配；威胁情报编译为拒绝规则",
    priorityWhitelist: "白名单",
    priorityWhitelistDetail: "最高优先级，命中后直接允许",
    protocol: "协议",
    query: "查询",
    refresh: "刷新",
    refreshCountryIps: "更新国家 IP 列表",
    refreshThreatFeeds: "更新威胁源",
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
    sourceIp: "源 IP",
    start: "开始",
    status: "状态",
    stop: "停止",
    stopped: "已停止",
    streaming: "订阅中",
    reason: "原因",
    tempBans: "临时封禁",
    tempBansHint: "临时封禁某个源 IP，可选协议和目的端口，默认 5 分钟",
    threats: "威胁",
    threatsHint: "配置威胁情报源，下发为拒绝规则",
    threatScore: "威胁评分",
    threatSource: "威胁源",
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
    apiAuth: "Authentication",
    apiAuthText: "Configuration, nodes, and Drop stream APIs require an API token except /health, /countries, and frontend assets. Both headers are accepted.",
    apiDocs: "API Docs",
    apiDocsHint: "HTTP control-plane API methods, parameters, and examples",
    apiPagination: "Pagination",
    apiPaginationText: "List APIs support page and page_size. The default page_size is 20 and the maximum is 500.",
    allNodes: "All nodes",
    allActions: "All actions",
    allCountries: "All countries",
    allFormats: "All formats",
    allProtocols: "All protocols",
    allStatuses: "All statuses",
    authInvalid: "missing or invalid API token",
    blockSeconds: "Block seconds",
    burst: "Burst",
    close: "Close",
    comment: "Comment",
    confirmDelete: "Delete this configuration?",
    countries: "Countries",
    countriesHint: "Allow or deny by country code",
    country: "Country",
    countryLookup: "IP Country Lookup",
    countryLookupHint: "Query the control-plane in-memory MMDB for an IP country",
    customRateLimits: "Custom Rate Limits",
    customRateLimitsHint: "Rate-limit by protocol or destination port before global IP limit and flood",
    delete: "Delete",
    disabledShort: "off",
    clear: "Clear",
    dropEvents: "Live Drops",
    dropEventsHint: "Subscribe to realtime drop events from agents through xDS",
    dropEventsLimit: "Keeping the latest 300 rows only",
    dropScope: "Scope",
    durationSeconds: "Duration seconds",
    dynamicDefense: "Dynamic Defense",
    dynamicDefenseHint: "Configure global per-source-IP rate limit and flood temporary block",
    deny: "deny",
    emptyCountries: "No country rules",
    emptyNodes: "No node heartbeats",
    emptyRules: "No firewall rules",
    emptyThreats: "No threat sources",
    emptyTrustedCidrs: "No whitelist entries",
    emptyDropEvents: "No drop events",
    emptyCustomRateLimits: "No custom rate limits",
    emptyTempBans: "No temporary bans",
    enabled: "Enabled",
    enabledShort: "on",
    error: "Error",
    expiresAt: "Expires at",
    floodBurst: "Flood burst",
    floodPps: "Flood PPS",
    format: "Format",
    firewall: "Firewall Config",
    help: "Help",
    helpHint: "Enforcement priority and API usage reference",
    highest: "highest",
    ipBurst: "IP burst",
    ipAddress: "IP address",
    ipPps: "IP PPS",
    interface: "Interface",
    name: "Name",
    node: "Node",
    nodes: "Nodes",
    page: "Page",
    policy: "Policy",
    port: "Port",
    priority: "Priority",
    ruleKey: "Rule key",
    priorityCountries: "Country rules",
    priorityCountriesDetail: "Then apply country-code allow or deny decisions",
    priorityTempBans: "Temporary bans",
    priorityTempBansDetail: "Drop matching temporary bans immediately after whitelist",
    priorityDefenseCustom: "Custom rate limits",
    priorityDefenseCustomDetail: "Apply protocol or destination-port dynamic rate limits first",
    priorityDefense: "Global Dynamic Defense",
    priorityDefenseDetail: "Finally apply global ip_rate_limit and flood",
    priorityOrder: "Enforcement Priority",
    priorityRules: "Firewall Rules / Threat Intel",
    priorityRulesDetail: "Rules match from lower numbers to higher numbers; threat intel is compiled as deny rules",
    priorityWhitelist: "Whitelist",
    priorityWhitelistDetail: "Highest priority; matching sources are allowed immediately",
    protocol: "Protocol",
    query: "Query",
    refresh: "Refresh",
    refreshCountryIps: "Refresh country IP lists",
    refreshThreatFeeds: "Refresh threat feeds",
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
    sourceIp: "Source IP",
    start: "Start",
    status: "Status",
    stop: "Stop",
    stopped: "stopped",
    streaming: "streaming",
    reason: "Reason",
    tempBans: "Temporary Bans",
    tempBansHint: "Temporarily block a source IP with optional protocol and destination port; default is 5 minutes",
    threats: "Threats",
    threatsHint: "Configure threat intelligence feeds as deny rules",
    threatScore: "Threat score",
    threatSource: "Threat source",
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
    ipNoCidr: (label: string) => `${label} 必须是单个 IP，不能填写 CIDR`,
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
    ipNoCidr: (label: string) => `${label} must be a single IP address, not CIDR`,
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

const apiDocsZh: ApiDocSection[] = [
  {
    title: "通用约定",
    description: "除 /health、/countries 和前端静态资源外都需要 API 令牌；请求头支持 Authorization: Bearer <token> 或 X-API-Token。错误响应为 {\"error\":\"...\"}。",
    endpoints: [
      { method: "GET", path: "分页接口", summary: "列表响应统一为 {items,total,page,page_size,total_pages}；page 默认 1，page_size 默认 20，最大 500。" },
      { method: "POST", path: "批量新增", summary: "批量新增请求体为 {\"items\":[...]}，items 必须非空且最多 500 项；每项格式同单条 POST。" },
      { method: "DELETE", path: "批量删除", summary: "批量删除请求体通常为 {\"ids\":[1,2]}，普通规则还支持 {\"ids\":[1,2],\"rule_keys\":[\"edge-web-deny\"]}；有效条目最多 500 项。" },
      { method: "POST", path: "写操作响应", summary: "大多数写操作返回 {version,data}；POST /policy/seed-example 返回策略快照本身。配置类 enabled 省略时默认 true。" },
      { method: "ANY", path: "字段约束", summary: "action 支持 allow、deny，drop 会归一化为 deny；protocol 支持 any、tcp、udp、icmp；port 范围 1-65535，icmp 不能设置 port。" },
      { method: "ANY", path: "/policies", summary: "多策略 API 已移除，/policies 和 /policies/{path} 会返回 404；请使用单策略资源接口。" }
    ]
  },
  {
    title: "系统",
    description: "健康检查、国家列表和策略版本。",
    endpoints: [
      { method: "GET", path: "/health", summary: "健康检查，公开接口。" },
      { method: "GET", path: "/countries", summary: "返回国家下拉列表，公开接口。" },
      { method: "GET", path: "/geo/lookup?ip=8.8.8.8", summary: "通过控制面内存 MMDB 查询 IP 归属国家。" },
      { method: "GET", path: "/policy/version", summary: "返回当前策略版本号。" },
      { method: "POST", path: "/policy/bump-version", summary: "手动递增策略版本，触发 xDS 推送。" },
      { method: "POST", path: "/policy/seed-example", summary: "初始化示例规则，保留白名单和动态防御配置。" }
    ]
  },
  {
    title: "普通规则",
    description: "CIDR、协议、端口的允许或拒绝规则。priority 数字越小优先级越高。",
    endpoints: [
      {
        method: "GET",
        path: "/rules?page=1&page_size=20&rule_key=edge-web-deny&action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10",
        summary: "分页列出普通防火墙规则，可按 rule_key、action、cidr、protocol、port、priority 过滤；过滤条件按 AND 匹配。"
      },
      {
        method: "POST",
        path: "/rules",
        summary: "新增普通规则。",
        body: `{
  "rule_key": "edge-web-deny",
  "priority": 10,
  "action": "deny",
  "cidr": "203.0.113.0/24",
  "protocol": "tcp",
  "port": 443,
  "comment": "block example"
}`,
        curl: `curl -X POST "$BASE/rules" \\
  -H "X-API-Token: $TOKEN" \\
  -H "content-type: application/json" \\
  -d '{"rule_key":"edge-web-deny","priority":10,"action":"deny","cidr":"203.0.113.0/24","protocol":"tcp","port":443}'`
      },
      { method: "POST", path: "/rules/batch", summary: "批量新增普通规则；请求体为 {\"items\":[...]}，每项格式同 POST /rules。" },
      { method: "DELETE", path: "/rules/{id}", summary: "按 id 删除普通规则。" },
      { method: "DELETE", path: "/rules/batch", summary: "按 id 和 rule_key 批量删除普通规则；请求体为 {\"ids\":[1,2],\"rule_keys\":[\"edge-web-deny\"]}，两者至少提供一个。" },
      {
        method: "DELETE",
        path: "/rules?action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10",
        summary: "按 action、cidr、protocol、port、priority 五元组删除普通规则，五个字段都必填并按 AND 匹配；也可以用 /rules?rule_key=edge-web-deny 按唯一规则键删除。"
      }
    ]
  },
  {
    title: "国家规则",
    description: "按国家代码允许或拒绝。国家名称和更新时间来自 IPdeny /ipblocks/ 页面，CIDR 从 aggregated 列表下载。",
    endpoints: [
      { method: "GET", path: "/geo-countries?page=1&page_size=20&country=CN&action=deny&enabled=true", summary: "分页列出国家规则，可按 country、action、enabled 过滤，条件按 AND 匹配。" },
      { method: "POST", path: "/geo-countries/refresh", summary: "异步启动所有国家 IP 列表刷新；5 分钟内重复调用直接返回上一次刷新结果。响应 data 包含 countries、checked_country_count、changed_country_count、failed_country_count、prefix_count、refresh_status、cached、running、errors。" },
      {
        method: "POST",
        path: "/geo-countries",
        summary: "新增国家允许或拒绝规则。",
        body: `{
  "country": "CN",
  "action": "allow"
}`
      },
      { method: "POST", path: "/geo-countries/batch", summary: "批量新增国家规则；请求体为 {\"items\":[...]}，每项格式同 POST /geo-countries。" },
      { method: "DELETE", path: "/geo-countries/{id}", summary: "按 id 删除国家规则。" },
      { method: "DELETE", path: "/geo-countries/batch", summary: "按 id 批量删除国家规则；请求体为 {\"ids\":[1,2]}。" },
      { method: "DELETE", path: "/geo-countries?country=CN&action=deny&enabled=true", summary: "按 country、action、enabled 删除国家规则，三个字段必填。" }
    ]
  },
  {
    title: "临时封禁",
    description: "临时封禁单个源 IP，可选协议和目的端口。duration_seconds 默认 300，必须大于 0，最大 31536000。",
    endpoints: [
      { method: "GET", path: "/temp-bans?page=1&page_size=20&ip=203.0.113.10&protocol=tcp&port=443", summary: "分页列出未过期临时封禁，可按 ip、protocol、port 过滤，条件按 AND 匹配。" },
      {
        method: "POST",
        path: "/temp-bans",
        summary: "新增临时封禁。",
        body: `{
  "ip": "203.0.113.10",
  "protocol": "tcp",
  "port": 443,
  "duration_seconds": 300,
  "comment": "manual block"
}`,
        curl: `curl -X POST "$BASE/temp-bans" \\
  -H "X-API-Token: $TOKEN" \\
  -H "content-type: application/json" \\
  -d '{"ip":"203.0.113.10","duration_seconds":300}'`
      },
      { method: "POST", path: "/temp-bans/batch", summary: "批量新增临时封禁；请求体为 {\"items\":[...]}，每项格式同 POST /temp-bans。" },
      { method: "DELETE", path: "/temp-bans/{id}", summary: "删除临时封禁，立即触发策略版本更新。" },
      { method: "DELETE", path: "/temp-bans/batch", summary: "按 id 批量删除临时封禁；请求体为 {\"ids\":[1,2]}。" }
    ]
  },
  {
    title: "威胁情报",
    description: "威胁源会被编译为拒绝前缀规则。format 支持 cidr、ips、ipsum、voipbl、spamhaus_drop；内置 ipsum、spamhaus-drop 和 voipbl。",
    endpoints: [
      { method: "GET", path: "/threat-sources?page=1&page_size=20&name=test-feed&format=ipsum&enabled=true", summary: "分页列出威胁源，可按 name、url、format、enabled、min_score 过滤；format 可为 cidr、ips、ipsum、voipbl、spamhaus_drop，条件按 AND 匹配。" },
      { method: "POST", path: "/threat-sources/refresh", summary: "异步刷新启用的威胁源；缺少持久化前缀时会绕过 5 分钟限流。响应 data 包含 enabled_source_count、changed_source_count、prefix_count、refreshed、refresh_status、cached、running。" },
      {
        method: "POST",
        path: "/threat-sources",
        summary: "新增威胁情报源；format 可为 cidr、ips、ipsum、voipbl、spamhaus_drop，也接受 voipbl_cidr、voipbl-cidr、spamhaus-drop 别名；启用的源会排队刷新并在前缀持久化后更新策略版本。",
        body: `{
  "name": "ipsum",
  "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
  "format": "ipsum",
  "min_score": 3
}`
      },
      { method: "POST", path: "/threat-sources/batch", summary: "批量新增威胁源；请求体为 {\"items\":[...]}，每项格式同 POST /threat-sources。" },
      { method: "DELETE", path: "/threat-sources/{id}", summary: "按 id 删除威胁源。" },
      { method: "DELETE", path: "/threat-sources/batch", summary: "按 id 批量删除威胁源；请求体为 {\"ids\":[1,2]}。" },
      { method: "DELETE", path: "/threat-sources?name=test-feed", summary: "按唯一 name 删除威胁源。" }
    ]
  },
  {
    title: "动态防御",
    description: "全局每源 IP 限流和 flood 临时封禁配置。",
    endpoints: [
      { method: "GET", path: "/dynamic-defense", summary: "读取全局动态防御配置。" },
      {
        method: "PUT",
        path: "/dynamic-defense",
        summary: "保存全局动态防御配置。",
        body: `{
  "enabled": true,
  "ip_rate_limit_enabled": true,
  "ip_packets_per_second": 5000,
  "ip_burst": 10000,
  "flood_enabled": true,
  "flood_packets_per_second": 20000,
  "flood_burst": 40000,
  "flood_block_seconds": 60
}`
      }
    ]
  },
  {
    title: "自定义限流",
    description: "按协议或目的端口配置动态防御限流，优先级高于全局 ip_rate_limit 和 flood。",
    endpoints: [
      { method: "GET", path: "/dynamic-rate-limits?page=1&page_size=20&enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000", summary: "分页列出自定义限流，可按 enabled、priority、protocol、port、packets_per_second、burst 过滤，条件按 AND 匹配。" },
      {
        method: "POST",
        path: "/dynamic-rate-limits",
        summary: "新增协议或目的端口限流。",
        body: `{
  "priority": 10,
  "protocol": "any",
  "port": 443,
  "packets_per_second": 1000,
  "burst": 2000,
  "comment": "protect https"
}`
      },
      { method: "POST", path: "/dynamic-rate-limits/batch", summary: "批量新增自定义限流；请求体为 {\"items\":[...]}，每项格式同 POST /dynamic-rate-limits。" },
      { method: "DELETE", path: "/dynamic-rate-limits/{id}", summary: "按 id 删除自定义限流。" },
      { method: "DELETE", path: "/dynamic-rate-limits/batch", summary: "按 id 批量删除自定义限流；请求体为 {\"ids\":[1,2]}。" },
      { method: "DELETE", path: "/dynamic-rate-limits?enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000", summary: "按完整限流配置删除；六个字段必填。没有存储端口的限流请按 id 删除。" }
    ]
  },
  {
    title: "白名单",
    description: "最高优先级源 CIDR 白名单。命中后直接允许。",
    endpoints: [
      { method: "GET", path: "/trusted-cidrs?page=1&page_size=20&cidr=10.0.0.0/8&enabled=true", summary: "分页列出数据库管理的白名单，可按 cidr、enabled 过滤，条件按 AND 匹配。" },
      {
        method: "POST",
        path: "/trusted-cidrs",
        summary: "新增或更新白名单 CIDR。",
        body: `{
  "cidr": "10.0.0.0/8",
  "enabled": true,
  "comment": "private network"
}`
      },
      { method: "POST", path: "/trusted-cidrs/batch", summary: "批量新增或更新白名单；请求体为 {\"items\":[...]}，每项格式同 POST /trusted-cidrs。" },
      { method: "DELETE", path: "/trusted-cidrs/{id}", summary: "按 id 删除白名单。" },
      { method: "DELETE", path: "/trusted-cidrs/batch", summary: "按 id 批量删除白名单；请求体为 {\"ids\":[1,2]}。" },
      { method: "DELETE", path: "/trusted-cidrs?cidr=10.0.0.0/8", summary: "按唯一 cidr 删除白名单。" }
    ]
  },
  {
    title: "节点",
    description: "查看 agent 心跳、最后应用版本和状态。",
    endpoints: [
      { method: "GET", path: "/nodes?page=1&page_size=20", summary: "分页列出节点。" },
      { method: "GET", path: "/nodes/{node_id}", summary: "查看单个节点状态。" }
    ]
  },
  {
    title: "实时 Drop",
    description: "NDJSON 流。事件字段包含 node_id、interface_name、time、event_time_ns、cpu、reason、src、family、proto、dport、country、threat_source、action。威胁情报 Drop 会补充 threat_source；无订阅时 agent 不读取 perf buffer，也不会开启 BPF drop event 输出。",
    endpoints: [
      {
        method: "GET",
        path: "/drop-events/stream",
        summary: "订阅所有节点实时 Drop。",
        curl: `curl -N "$BASE/drop-events/stream" -H "X-API-Token: $TOKEN"`
      },
      {
        method: "GET",
        path: "/drop-events/stream?node_id=node-1",
        summary: "只订阅指定节点实时 Drop。",
        curl: `curl -N "$BASE/drop-events/stream?node_id=node-1" -H "X-API-Token: $TOKEN"`
      }
    ]
  }
];

const apiDocsEn: ApiDocSection[] = [
  {
    title: "Conventions",
    description: "All APIs except /health, /countries, and frontend assets require an API token. Send either Authorization: Bearer <token> or X-API-Token. Error responses are {\"error\":\"...\"}.",
    endpoints: [
      { method: "GET", path: "Paginated APIs", summary: "List responses are {items,total,page,page_size,total_pages}; page defaults to 1, page_size defaults to 20, and the maximum page_size is 500." },
      { method: "POST", path: "Batch create", summary: "Batch create bodies are {\"items\":[...]}; items must be non-empty and contain at most 500 entries. Each item matches the single-row POST shape." },
      { method: "DELETE", path: "Batch delete", summary: "Batch delete bodies are {\"ids\":[1,2]}; ids must be non-empty and contain at most 500 entries." },
      { method: "POST", path: "Write responses", summary: "Most write APIs return {version,data}; POST /policy/seed-example returns the policy snapshot directly. Configuration enabled fields default to true when omitted." },
      { method: "ANY", path: "Field rules", summary: "action supports allow and deny; drop is normalized to deny. protocol supports any, tcp, udp, and icmp. port must be 1-65535, and icmp cannot set a port." },
      { method: "ANY", path: "/policies", summary: "Multi-policy APIs are removed. /policies and /policies/{path} return 404; use the single-policy resource endpoints." }
    ]
  },
  {
    title: "System",
    description: "Health, country options, and policy version.",
    endpoints: [
      { method: "GET", path: "/health", summary: "Health check. Public." },
      { method: "GET", path: "/countries", summary: "Country dropdown options. Public." },
      { method: "GET", path: "/geo/lookup?ip=8.8.8.8", summary: "Query the control-plane in-memory MMDB for an IP country." },
      { method: "GET", path: "/policy/version", summary: "Return the current policy version number." },
      { method: "POST", path: "/policy/bump-version", summary: "Increment the policy version and trigger xDS push." },
      { method: "POST", path: "/policy/seed-example", summary: "Seed example rules while preserving whitelist and dynamic defense settings." }
    ]
  },
  {
    title: "Firewall Rules",
    description: "CIDR/protocol/port allow or deny rules. Lower priority numbers win.",
    endpoints: [
      {
        method: "GET",
        path: "/rules?page=1&page_size=20&rule_key=edge-web-deny&action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10",
        summary: "List firewall rules, optionally filtered by rule_key, action, cidr, protocol, port, and priority with AND semantics."
      },
      {
        method: "POST",
        path: "/rules",
        summary: "Create a firewall rule.",
        body: `{
  "rule_key": "edge-web-deny",
  "priority": 10,
  "action": "deny",
  "cidr": "203.0.113.0/24",
  "protocol": "tcp",
  "port": 443,
  "comment": "block example"
}`,
        curl: `curl -X POST "$BASE/rules" \\
  -H "X-API-Token: $TOKEN" \\
  -H "content-type: application/json" \\
  -d '{"rule_key":"edge-web-deny","priority":10,"action":"deny","cidr":"203.0.113.0/24","protocol":"tcp","port":443}'`
      },
      { method: "POST", path: "/rules/batch", summary: "Create firewall rules in one request; body is {\"items\":[...]} and each item matches POST /rules." },
      { method: "DELETE", path: "/rules/{id}", summary: "Delete a firewall rule by id." },
      { method: "DELETE", path: "/rules/batch", summary: "Delete firewall rules by id in one request; body is {\"ids\":[1,2]}." },
      {
        method: "DELETE",
        path: "/rules?action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10",
        summary: "Delete firewall rules by action, cidr, protocol, port, and priority; all five fields are required and matched with AND semantics. Use /rules?rule_key=edge-web-deny to delete by unique rule key."
      }
    ]
  },
  {
    title: "Country Rules",
    description: "Allow or deny by country code. Country names and update metadata come from IPdeny /ipblocks/; CIDRs are downloaded from aggregated lists.",
    endpoints: [
      { method: "GET", path: "/geo-countries?page=1&page_size=20&country=CN&action=deny&enabled=true", summary: "List country rules, optionally filtered by country, action, and enabled with AND semantics." },
      { method: "POST", path: "/geo-countries/refresh", summary: "Start an async refresh for all country IP lists; repeated calls within 5 minutes return the previous result. data includes countries, checked_country_count, changed_country_count, failed_country_count, prefix_count, refresh_status, cached, running, and errors." },
      {
        method: "POST",
        path: "/geo-countries",
        summary: "Create a country allow or deny rule.",
        body: `{
  "country": "CN",
  "action": "allow"
}`
      },
      { method: "POST", path: "/geo-countries/batch", summary: "Create country rules in one request; body is {\"items\":[...]} and each item matches POST /geo-countries." },
      { method: "DELETE", path: "/geo-countries/{id}", summary: "Delete a country rule by id." },
      { method: "DELETE", path: "/geo-countries/batch", summary: "Delete country rules by id in one request; body is {\"ids\":[1,2]}." },
      { method: "DELETE", path: "/geo-countries?country=CN&action=deny&enabled=true", summary: "Delete a country rule by country, action, and enabled; all three fields are required." }
    ]
  },
  {
    title: "Temporary Bans",
    description: "Temporarily block one source IP with optional protocol and destination port. duration_seconds defaults to 300, must be greater than 0, and is capped at 31536000.",
    endpoints: [
      { method: "GET", path: "/temp-bans?page=1&page_size=20&ip=203.0.113.10&protocol=tcp&port=443", summary: "List unexpired temporary bans, optionally filtered by ip, protocol, and port with AND semantics." },
      {
        method: "POST",
        path: "/temp-bans",
        summary: "Create a temporary ban.",
        body: `{
  "ip": "203.0.113.10",
  "protocol": "tcp",
  "port": 443,
  "duration_seconds": 300,
  "comment": "manual block"
}`,
        curl: `curl -X POST "$BASE/temp-bans" \\
  -H "X-API-Token: $TOKEN" \\
  -H "content-type: application/json" \\
  -d '{"ip":"203.0.113.10","duration_seconds":300}'`
      },
      { method: "POST", path: "/temp-bans/batch", summary: "Create temporary bans in one request; body is {\"items\":[...]} and each item matches POST /temp-bans." },
      { method: "DELETE", path: "/temp-bans/{id}", summary: "Delete a temporary ban and trigger a new policy version." },
      { method: "DELETE", path: "/temp-bans/batch", summary: "Delete temporary bans by id in one request; body is {\"ids\":[1,2]}." }
    ]
  },
  {
    title: "Threat Intelligence",
    description: "Threat feeds compile into deny prefix rules. Supported format values are cidr, ips, ipsum, voipbl, and spamhaus_drop; built-ins include ipsum, spamhaus-drop, and voipbl.",
    endpoints: [
      { method: "GET", path: "/threat-sources?page=1&page_size=20&name=test-feed&format=ipsum&enabled=true", summary: "List threat sources, optionally filtered by name, url, format, enabled, and min_score. Supported format values are cidr, ips, ipsum, voipbl, and spamhaus_drop; filters use AND semantics." },
      { method: "POST", path: "/threat-sources/refresh", summary: "Start an async refresh for enabled threat feeds; missing persisted prefixes bypass the 5-minute rate limit. data includes enabled_source_count, changed_source_count, prefix_count, refreshed, refresh_status, cached, and running." },
      {
        method: "POST",
        path: "/threat-sources",
        summary: "Create a threat feed; format can be cidr, ips, ipsum, voipbl, or spamhaus_drop, with aliases voipbl_cidr, voipbl-cidr, and spamhaus-drop. Enabled feeds queue a refresh and update the policy version after prefixes are persisted.",
        body: `{
  "name": "ipsum",
  "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
  "format": "ipsum",
  "min_score": 3
}`
      },
      { method: "POST", path: "/threat-sources/batch", summary: "Create threat sources in one request; body is {\"items\":[...]} and each item matches POST /threat-sources." },
      { method: "DELETE", path: "/threat-sources/{id}", summary: "Delete a threat source by id." },
      { method: "DELETE", path: "/threat-sources/batch", summary: "Delete threat sources by id in one request; body is {\"ids\":[1,2]}." },
      { method: "DELETE", path: "/threat-sources?name=test-feed", summary: "Delete a threat source by its unique name." }
    ]
  },
  {
    title: "Dynamic Defense",
    description: "Global per-source-IP rate limit and flood temporary block settings.",
    endpoints: [
      { method: "GET", path: "/dynamic-defense", summary: "Read global dynamic defense settings." },
      {
        method: "PUT",
        path: "/dynamic-defense",
        summary: "Save global dynamic defense settings.",
        body: `{
  "enabled": true,
  "ip_rate_limit_enabled": true,
  "ip_packets_per_second": 5000,
  "ip_burst": 10000,
  "flood_enabled": true,
  "flood_packets_per_second": 20000,
  "flood_burst": 40000,
  "flood_block_seconds": 60
}`
      }
    ]
  },
  {
    title: "Custom Rate Limits",
    description: "Protocol or destination-port dynamic defense limits. They run before global ip_rate_limit and flood.",
    endpoints: [
      { method: "GET", path: "/dynamic-rate-limits?page=1&page_size=20&enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000", summary: "List custom rate limits, optionally filtered by enabled, priority, protocol, port, packets_per_second, and burst with AND semantics." },
      {
        method: "POST",
        path: "/dynamic-rate-limits",
        summary: "Create a protocol or destination-port limit.",
        body: `{
  "priority": 10,
  "protocol": "any",
  "port": 443,
  "packets_per_second": 1000,
  "burst": 2000,
  "comment": "protect https"
}`
      },
      { method: "POST", path: "/dynamic-rate-limits/batch", summary: "Create custom rate limits in one request; body is {\"items\":[...]} and each item matches POST /dynamic-rate-limits." },
      { method: "DELETE", path: "/dynamic-rate-limits/{id}", summary: "Delete a custom rate limit by id." },
      { method: "DELETE", path: "/dynamic-rate-limits/batch", summary: "Delete custom rate limits by id in one request; body is {\"ids\":[1,2]}." },
      { method: "DELETE", path: "/dynamic-rate-limits?enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000", summary: "Delete by the complete rate-limit configuration; all six fields are required. Use id for limits without a stored port." }
    ]
  },
  {
    title: "Whitelist",
    description: "Highest-priority source CIDR whitelist. Matching sources pass immediately.",
    endpoints: [
      { method: "GET", path: "/trusted-cidrs?page=1&page_size=20&cidr=10.0.0.0/8&enabled=true", summary: "List database-managed whitelist entries, optionally filtered by cidr and enabled with AND semantics." },
      {
        method: "POST",
        path: "/trusted-cidrs",
        summary: "Create or update a whitelist CIDR.",
        body: `{
  "cidr": "10.0.0.0/8",
  "enabled": true,
  "comment": "private network"
}`
      },
      { method: "POST", path: "/trusted-cidrs/batch", summary: "Create or update whitelist entries in one request; body is {\"items\":[...]} and each item matches POST /trusted-cidrs." },
      { method: "DELETE", path: "/trusted-cidrs/{id}", summary: "Delete a whitelist entry by id." },
      { method: "DELETE", path: "/trusted-cidrs/batch", summary: "Delete whitelist entries by id in one request; body is {\"ids\":[1,2]}." },
      { method: "DELETE", path: "/trusted-cidrs?cidr=10.0.0.0/8", summary: "Delete a whitelist entry by its unique cidr." }
    ]
  },
  {
    title: "Nodes",
    description: "Agent heartbeat, last applied version, and status.",
    endpoints: [
      { method: "GET", path: "/nodes?page=1&page_size=20", summary: "List nodes." },
      { method: "GET", path: "/nodes/{node_id}", summary: "Read one node." }
    ]
  },
  {
    title: "Live Drop Events",
    description: "NDJSON stream. Event fields include node_id, interface_name, time, event_time_ns, cpu, reason, src, family, proto, dport, country, threat_source, and action. Threat-intel drops include threat_source; agents do not read the perf buffer or enable BPF drop event output when there are no subscribers.",
    endpoints: [
      {
        method: "GET",
        path: "/drop-events/stream",
        summary: "Subscribe to all nodes.",
        curl: `curl -N "$BASE/drop-events/stream" -H "X-API-Token: $TOKEN"`
      },
      {
        method: "GET",
        path: "/drop-events/stream?node_id=node-1",
        summary: "Subscribe to one node.",
        curl: `curl -N "$BASE/drop-events/stream?node_id=node-1" -H "X-API-Token: $TOKEN"`
      }
    ]
  }
];

type TextKey = keyof typeof messages.zh;
type ValidationKey = keyof typeof validationMessages.zh;

const priorityOrder: { rank: string; label: TextKey; detail: TextKey }[] = [
  { rank: "1", label: "priorityWhitelist", detail: "priorityWhitelistDetail" },
  { rank: "2", label: "priorityTempBans", detail: "priorityTempBansDetail" },
  { rank: "3", label: "priorityRules", detail: "priorityRulesDetail" },
  { rank: "4", label: "priorityCountries", detail: "priorityCountriesDetail" },
  { rank: "5", label: "priorityDefenseCustom", detail: "priorityDefenseCustomDetail" },
  { rank: "6", label: "priorityDefense", detail: "priorityDefenseDetail" }
];

const pageResponseExample = `{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20,
  "total_pages": 0
}`;

const apiDocSections = computed<ApiDocSection[]>(() => {
  if (language.value === "en") {
    return apiDocsEn;
  }
  return apiDocsZh;
});

const highestRulePriority = computed(() => {
  if (rules.value.length === 0) {
    return null;
  }
  return Math.min(...rules.value.map((rule) => rule.priority));
});

function isHighestRule(rule: Rule): boolean {
  return highestRulePriority.value !== null && rule.priority === highestRulePriority.value;
}

const highestDynamicRateLimitPriority = computed(() => {
  if (dynamicRateLimits.value.length === 0) {
    return null;
  }
  return Math.min(...dynamicRateLimits.value.map((limit) => limit.priority));
});

function isHighestDynamicRateLimit(limit: DynamicRateLimit): boolean {
  return highestDynamicRateLimitPriority.value !== null && limit.priority === highestDynamicRateLimitPriority.value;
}

function methodTone(method: string): "red" | "amber" | "green" | "neutral" {
  if (method === "GET") {
    return "green";
  }
  if (method === "DELETE") {
    return "red";
  }
  if (method === "POST" || method === "PUT") {
    return "amber";
  }
  return "neutral";
}

const filteredDropEvents = computed(() => {
  const src = dropFilters.src.trim().toLowerCase();
  const proto = dropFilters.proto;
  const port = dropFilters.port.trim();
  return dropEvents.value.filter((event) => {
    if (src && !event.src.toLowerCase().includes(src)) {
      return false;
    }
    if (proto !== "all" && event.proto.toLowerCase() !== proto) {
      return false;
    }
    if (port && String(event.dport || "*") !== port) {
      return false;
    }
    return true;
  });
});

const geoLookupLabel = computed(() => {
  const result = geoLookupResult.value;
  if (!result?.country) {
    return "-";
  }
  return result.country_name ? `${result.country} · ${result.country_name}` : result.country;
});

function formatLocalTime(value: string | null | undefined) {
  const text = String(value ?? "").trim();
  if (!text) {
    return "-";
  }
  const date = new Date(timestampWithUtcDefault(text));
  if (Number.isNaN(date.getTime())) {
    return text;
  }
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function timestampWithUtcDefault(value: string) {
  if (/([zZ]|[+-]\d{2}:?\d{2})$/.test(value)) {
    return value;
  }
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(value)) {
    return `${value.replace(" ", "T")}Z`;
  }
  return value;
}

function countryRefreshNotice(result: GeoRefreshResponse) {
  if (language.value === "zh") {
    if (result.running && result.cached) {
      return "国家 IP 刷新正在后台执行，当前显示上一次刷新结果";
    }
    if (result.running) {
      return "国家 IP 刷新已在后台启动";
    }
    if (result.refresh_status === "rate_limited" && result.cached) {
      return "国家 IP 刷新处于限流窗口内，已返回上一次刷新结果";
    }
    if (result.refresh_status === "rate_limited") {
      return "国家 IP 刷新处于限流窗口内，暂无上一次刷新结果";
    }
    if (result.changed_country_count === 0) {
      return `已检查 ${result.checked_country_count} 个国家，远端未更新`;
    }
    return `已更新 ${result.changed_country_count}/${result.checked_country_count} 个国家，拉取 ${result.prefix_count} 条 CIDR`;
  }
  if (result.running && result.cached) {
    return "Country IP refresh is running in the background; showing the previous result";
  }
  if (result.running) {
    return "Country IP refresh started in the background";
  }
  if (result.refresh_status === "rate_limited" && result.cached) {
    return "Country IP refresh is rate limited; showing the previous result";
  }
  if (result.refresh_status === "rate_limited") {
    return "Country IP refresh is rate limited; no previous result is available yet";
  }
  if (result.changed_country_count === 0) {
    return `Checked ${result.checked_country_count} countries; no upstream changes`;
  }
  return `Updated ${result.changed_country_count}/${result.checked_country_count} countries and fetched ${result.prefix_count} CIDRs`;
}

function threatRefreshNotice(result: ThreatRefreshResponse) {
  if (language.value === "zh") {
    if (result.running && result.cached) {
      return "威胁源刷新正在后台执行，当前显示上一次刷新结果";
    }
    if (result.running) {
      return "威胁源刷新已在后台启动";
    }
    if (result.refresh_status === "rate_limited" && result.cached) {
      return "威胁源刷新处于限流窗口内，已返回上一次刷新结果";
    }
    if (result.refresh_status === "rate_limited") {
      return "威胁源刷新处于限流窗口内，暂无上一次刷新结果";
    }
    if (result.refresh_status === "empty") {
      return "没有启用的威胁源需要刷新";
    }
    if (result.changed_source_count === 0) {
      return `已检查 ${result.enabled_source_count} 个威胁源，远端未更新`;
    }
    return `已更新 ${result.changed_source_count}/${result.enabled_source_count} 个威胁源，解析 ${result.prefix_count} 条前缀`;
  }
  if (result.running && result.cached) {
    return "Threat feed refresh is running in the background; showing the previous result";
  }
  if (result.running) {
    return "Threat feed refresh started in the background";
  }
  if (result.refresh_status === "rate_limited" && result.cached) {
    return "Threat feed refresh is rate limited; showing the previous result";
  }
  if (result.refresh_status === "rate_limited") {
    return "Threat feed refresh is rate limited; no previous result is available yet";
  }
  if (result.refresh_status === "empty") {
    return "No enabled threat feeds need refresh";
  }
  if (result.changed_source_count === 0) {
    return `Checked ${result.enabled_source_count} threat feeds; no upstream changes`;
  }
  return `Updated ${result.changed_source_count}/${result.enabled_source_count} threat feeds and parsed ${result.prefix_count} prefixes`;
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
    clean.startsWith("geo/") ||
    clean.startsWith("geo-countries") ||
    clean.startsWith("temp-bans") ||
    clean.startsWith("threat-sources") ||
    clean.startsWith("dynamic-defense") ||
    clean.startsWith("dynamic-rate-limits") ||
    clean.startsWith("trusted-cidrs") ||
    clean.startsWith("nodes") ||
    clean.startsWith("drop-events")
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
  localStorage.removeItem("xdp-firewall-api-token");
  const token = apiToken.value.trim();
  if (token) {
    sessionStorage.setItem("xdp-firewall-api-token", token);
  } else {
    sessionStorage.removeItem("xdp-firewall-api-token");
  }
}

function currentApiToken(): string {
  return apiToken.value.trim();
}

function clearApiToken() {
  stopDropStream();
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

const helpFabStyle = computed(() => {
  if (helpFabPosition.left === null || helpFabPosition.top === null) {
    return {};
  }
  return {
    left: `${helpFabPosition.left}px`,
    top: `${helpFabPosition.top}px`,
    right: "auto",
    bottom: "auto"
  };
});

function startHelpFabDrag(event: PointerEvent) {
  if (event.button !== 0) {
    return;
  }
  const button = event.currentTarget as HTMLElement;
  const rect = button.getBoundingClientRect();
  if (helpFabPosition.left === null || helpFabPosition.top === null) {
    helpFabPosition.left = rect.left;
    helpFabPosition.top = rect.top;
  }
  helpFabStart = { x: event.clientX, y: event.clientY, left: rect.left, top: rect.top };
  helpFabMoved.value = false;
  helpFabDragging.value = true;
  button.setPointerCapture(event.pointerId);
}

function moveHelpFab(event: PointerEvent) {
  if (!helpFabDragging.value) {
    return;
  }
  const button = event.currentTarget as HTMLElement;
  const rect = button.getBoundingClientRect();
  const dx = event.clientX - helpFabStart.x;
  const dy = event.clientY - helpFabStart.y;
  helpFabMoved.value ||= Math.abs(dx) > 4 || Math.abs(dy) > 4;
  const maxLeft = Math.max(8, window.innerWidth - rect.width - 8);
  const maxTop = Math.max(8, window.innerHeight - rect.height - 8);
  helpFabPosition.left = Math.min(maxLeft, Math.max(8, helpFabStart.left + dx));
  helpFabPosition.top = Math.min(maxTop, Math.max(8, helpFabStart.top + dy));
}

function endHelpFabDrag(event: PointerEvent) {
  if (!helpFabDragging.value) {
    return;
  }
  const button = event.currentTarget as HTMLElement;
  if (button.hasPointerCapture(event.pointerId)) {
    button.releasePointerCapture(event.pointerId);
  }
  helpFabDragging.value = false;
}

function openHelpFromFab() {
  if (helpFabMoved.value) {
    helpFabMoved.value = false;
    return;
  }
  helpOpen.value = true;
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
  if (value === "apiDocs") {
    helpOpen.value = true;
    tab.value = "rules";
    return;
  }
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

function rulePageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (ruleFilters.rule_key.trim()) {
    params.set("rule_key", ruleFilters.rule_key.trim());
  }
  if (ruleFilters.action !== "all") {
    params.set("action", ruleFilters.action);
  }
  if (ruleFilters.cidr.trim()) {
    params.set("cidr", ruleFilters.cidr.trim());
  }
  if (ruleFilters.protocol !== "all") {
    params.set("protocol", ruleFilters.protocol);
  }
  if (ruleFilters.port.trim()) {
    params.set("port", ruleFilters.port.trim());
  }
  if (ruleFilters.priority.trim()) {
    params.set("priority", ruleFilters.priority.trim());
  }
  return params.toString();
}

function trustedPageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (trustedFilters.cidr.trim()) {
    params.set("cidr", trustedFilters.cidr.trim());
  }
  if (trustedFilters.enabled !== "all") {
    params.set("enabled", trustedFilters.enabled);
  }
  return params.toString();
}

function geoPageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (geoFilters.country !== "all") {
    params.set("country", geoFilters.country);
  }
  if (geoFilters.action !== "all") {
    params.set("action", geoFilters.action);
  }
  if (geoFilters.enabled !== "all") {
    params.set("enabled", geoFilters.enabled);
  }
  return params.toString();
}

function tempBanPageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (tempBanFilters.ip.trim()) {
    params.set("ip", tempBanFilters.ip.trim());
  }
  if (tempBanFilters.protocol !== "all") {
    params.set("protocol", tempBanFilters.protocol);
  }
  if (tempBanFilters.port.trim()) {
    params.set("port", tempBanFilters.port.trim());
  }
  return params.toString();
}

function threatPageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (threatFilters.name.trim()) {
    params.set("name", threatFilters.name.trim());
  }
  if (threatFilters.url.trim()) {
    params.set("url", threatFilters.url.trim());
  }
  if (threatFilters.format !== "all") {
    params.set("format", threatFilters.format);
  }
  if (threatFilters.enabled !== "all") {
    params.set("enabled", threatFilters.enabled);
  }
  if (threatFilters.min_score.trim()) {
    params.set("min_score", threatFilters.min_score.trim());
  }
  return params.toString();
}

function dynamicRatePageQuery(page: number): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (dynamicRateFilters.priority.trim()) {
    params.set("priority", dynamicRateFilters.priority.trim());
  }
  if (dynamicRateFilters.protocol !== "all") {
    params.set("protocol", dynamicRateFilters.protocol);
  }
  if (dynamicRateFilters.port.trim()) {
    params.set("port", dynamicRateFilters.port.trim());
  }
  if (dynamicRateFilters.packets_per_second.trim()) {
    params.set("packets_per_second", dynamicRateFilters.packets_per_second.trim());
  }
  if (dynamicRateFilters.burst.trim()) {
    params.set("burst", dynamicRateFilters.burst.trim());
  }
  if (dynamicRateFilters.enabled !== "all") {
    params.set("enabled", dynamicRateFilters.enabled);
  }
  return params.toString();
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

function dropReasonLabel(reason: string): string {
  const zh: Record<string, string> = {
    firewall_rule: "普通规则",
    threat_intel: "威胁情报",
    country: "国家",
    temporary_ban: "临时封禁",
    "dynamic_defense.ip_rate_limit": "动态防御 IP 限流",
    "dynamic_defense.flood": "动态防御 Flood",
    "dynamic_defense.custom_rate_limit": "动态防御自定义限流",
    parse_error: "解析异常"
  };
  const en: Record<string, string> = {
    firewall_rule: "Firewall rule",
    threat_intel: "Threat intel",
    country: "Country",
    temporary_ban: "Temporary ban",
    "dynamic_defense.ip_rate_limit": "IP rate limit",
    "dynamic_defense.flood": "Flood",
    "dynamic_defense.custom_rate_limit": "Custom rate limit",
    parse_error: "Parse error"
  };
  return (language.value === "zh" ? zh : en)[reason] ?? reason;
}

function dropReasonTone(reason: string): "red" | "amber" | "green" | "neutral" {
  if (reason === "threat_intel" || reason === "country" || reason === "temporary_ban") {
    return "red";
  }
  if (reason.startsWith("dynamic_defense")) {
    return "amber";
  }
  return "neutral";
}

function countryLabel(country: CountryOption): string {
  return `${country.code} · ${country.name}`;
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
  loading.value = true;
  try {
    await loadHealth();
    await loadPolicy();
    await loadTabData(tab.value);
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  } finally {
    loading.value = false;
  }
}

async function refreshPublic() {
  loading.value = true;
  try {
    await loadHealth();
    if (tab.value === "geo") {
      await loadCountries();
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err);
  } finally {
    loading.value = false;
  }
}

async function refreshCurrentView() {
  await refreshAll();
}

async function ensureTabLoaded(value: (typeof tabs)[number]["id"]) {
  if (loadedTabs.has(value)) {
    return;
  }
  const pending = pendingTabLoads.get(value);
  if (pending) {
    await pending;
    return;
  }
  const load = loadTabData(value).then(() => {
    loadedTabs.add(value);
  });
  pendingTabLoads.set(value, load);
  try {
    await load;
  } finally {
    pendingTabLoads.delete(value);
  }
}

async function loadTabData(value: (typeof tabs)[number]["id"]) {
  switch (value) {
    case "rules":
      await loadRules();
      break;
    case "geo":
      await loadCountries();
      await loadGeo();
      break;
    case "tempBans":
      await loadTempBans();
      break;
    case "threats":
      await loadThreats();
      break;
    case "defense":
      await loadDynamicDefense();
      await loadDynamicRateLimits();
      break;
    case "trusted":
      await loadTrustedCidrs();
      break;
    case "nodes":
      await loadNodes();
      break;
    case "drops":
      break;
  }
  loadedTabs.add(value);
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
  snapshot.value = await api<Snapshot>("policy/version");
}

async function loadRules(page = rulePage.page) {
  const data = await api<Page<Rule>>(`rules?${rulePageQuery(page)}`);
  rules.value = data.items;
  updatePage(rulePage, data);
}

const hasRuleFilters = computed(() => {
  return ruleFilters.action !== "all" || ruleFilters.protocol !== "all" || Boolean(ruleFilters.rule_key.trim() || ruleFilters.cidr.trim() || ruleFilters.port.trim() || ruleFilters.priority.trim());
});

async function queryRules() {
  await loadRules(1);
}

async function clearRuleFilters() {
  ruleFilters.rule_key = "";
  ruleFilters.action = "all";
  ruleFilters.cidr = "";
  ruleFilters.protocol = "all";
  ruleFilters.port = "";
  ruleFilters.priority = "";
  await loadRules(1);
}

async function loadGeo(page = geoPage.page) {
  const data = await api<Page<GeoCountry>>(`geo-countries?${geoPageQuery(page)}`);
  geoCountries.value = data.items;
  updatePage(geoPage, data);
}

async function loadTempBans(page = tempBanPage.page) {
  const data = await api<Page<TempBan>>(`temp-bans?${tempBanPageQuery(page)}`);
  tempBans.value = data.items;
  updatePage(tempBanPage, data);
}

async function loadThreats(page = threatPage.page) {
  const data = await api<Page<ThreatSource>>(`threat-sources?${threatPageQuery(page)}`);
  threatSources.value = data.items;
  updatePage(threatPage, data);
}

const hasGeoFilters = computed(() => {
  return geoFilters.country !== "all" || geoFilters.action !== "all" || geoFilters.enabled !== "all";
});

async function queryGeo() {
  await loadGeo(1);
}

async function clearGeoFilters() {
  geoFilters.country = "all";
  geoFilters.action = "all";
  geoFilters.enabled = "all";
  await loadGeo(1);
}

const hasTempBanFilters = computed(() => {
  return Boolean(tempBanFilters.ip.trim() || tempBanFilters.port.trim()) || tempBanFilters.protocol !== "all";
});

async function queryTempBans() {
  await loadTempBans(1);
}

async function clearTempBanFilters() {
  tempBanFilters.ip = "";
  tempBanFilters.protocol = "all";
  tempBanFilters.port = "";
  await loadTempBans(1);
}

const hasThreatFilters = computed(() => {
  return Boolean(threatFilters.name.trim() || threatFilters.url.trim() || threatFilters.min_score.trim()) || threatFilters.format !== "all" || threatFilters.enabled !== "all";
});

async function queryThreats() {
  await loadThreats(1);
}

async function clearThreatFilters() {
  threatFilters.name = "";
  threatFilters.url = "";
  threatFilters.format = "all";
  threatFilters.enabled = "all";
  threatFilters.min_score = "";
  await loadThreats(1);
}

async function loadDynamicDefense() {
  const data = await api<DynamicDefense>("dynamic-defense");
  Object.assign(dynamicDefense, data);
}

async function loadDynamicRateLimits(page = dynamicRatePage.page) {
  const data = await api<Page<DynamicRateLimit>>(`dynamic-rate-limits?${dynamicRatePageQuery(page)}`);
  dynamicRateLimits.value = data.items;
  updatePage(dynamicRatePage, data);
}

const hasDynamicRateFilters = computed(() => {
  return Boolean(dynamicRateFilters.priority.trim() || dynamicRateFilters.port.trim() || dynamicRateFilters.packets_per_second.trim() || dynamicRateFilters.burst.trim()) || dynamicRateFilters.protocol !== "all" || dynamicRateFilters.enabled !== "all";
});

async function queryDynamicRateLimits() {
  await loadDynamicRateLimits(1);
}

async function clearDynamicRateFilters() {
  dynamicRateFilters.priority = "";
  dynamicRateFilters.protocol = "all";
  dynamicRateFilters.port = "";
  dynamicRateFilters.packets_per_second = "";
  dynamicRateFilters.burst = "";
  dynamicRateFilters.enabled = "all";
  await loadDynamicRateLimits(1);
}

async function loadTrustedCidrs(page = trustedPage.page) {
  const data = await api<Page<TrustedCidr>>(`trusted-cidrs?${trustedPageQuery(page)}`);
  trustedCidrs.value = data.items;
  updatePage(trustedPage, data);
}

const hasTrustedFilters = computed(() => {
  return Boolean(trustedFilters.cidr.trim()) || trustedFilters.enabled !== "all";
});

async function queryTrustedCidrs() {
  await loadTrustedCidrs(1);
}

async function clearTrustedFilters() {
  trustedFilters.cidr = "";
  trustedFilters.enabled = "all";
  await loadTrustedCidrs(1);
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

async function startDropStream() {
  if (dropStreaming.value) {
    return;
  }
  error.value = "";
  const headers = new Headers();
  const token = currentApiToken();
  if (!token) {
    authRequired.value = true;
    loginError.value = t("authInvalid");
    return;
  }
  headers.set(authHeader, `Bearer ${token}`);
  headers.set(apiTokenHeader, token);
  dropAbort = new AbortController();
  dropStreaming.value = true;
  try {
    const response = await fetch(apiUrl(dropStreamPath()), {
      headers,
      signal: dropAbort.signal
    });
    if (response.status === 401) {
      authRequired.value = true;
      loginError.value = t("authInvalid");
      return;
    }
    if (!response.ok || !response.body) {
      throw new Error(response.statusText || "drop stream failed");
    }
    await readDropStream(response.body);
  } catch (err) {
    if (!(err instanceof DOMException && err.name === "AbortError")) {
      error.value = err instanceof Error ? err.message : String(err);
    }
  } finally {
    dropStreaming.value = false;
    dropAbort = null;
  }
}

function dropStreamPath(): string {
  if (dropNodeFilter.value === "all") {
    return "drop-events/stream";
  }
  return `drop-events/stream?node_id=${encodeURIComponent(dropNodeFilter.value)}`;
}

function stopDropStream() {
  dropAbort?.abort();
  dropAbort = null;
  dropStreaming.value = false;
}

function clearDropEvents() {
  dropEvents.value = [];
}

async function readDropStream(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    buffered += decoder.decode(value, { stream: true });
    const lines = buffered.split("\n");
    buffered = lines.pop() ?? "";
    for (const line of lines) {
      appendDropEvent(line);
    }
  }
}

function appendDropEvent(line: string) {
  const trimmed = line.trim();
  if (!trimmed) {
    return;
  }
  let event: Omit<DropEvent, "local_id">;
  try {
    event = JSON.parse(trimmed) as Omit<DropEvent, "local_id">;
  } catch (err) {
    console.warn("ignored invalid drop event line", err);
    return;
  }
  dropEvents.value.unshift({ ...event, local_id: ++dropEventSeq });
  if (dropEvents.value.length > 300) {
    dropEvents.value.length = 300;
  }
}

async function seedExample() {
  await api("policy/seed-example", { method: "POST" });
  await refreshAll();
  showNotice(t("saved"));
}

async function createRule() {
  validateFields(["ruleCidr", "rulePort"]);
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

async function refreshGeoCountries() {
  const result = await api<Versioned<GeoRefreshResponse>>("geo-countries/refresh", {
    method: "POST"
  });
  await refreshAll();
  showNotice(countryRefreshNotice(result.data));
}

async function refreshThreatSources() {
  const result = await api<Versioned<ThreatRefreshResponse>>("threat-sources/refresh", {
    method: "POST"
  });
  await refreshAll();
  showNotice(threatRefreshNotice(result.data));
}

async function lookupGeoIp() {
  validateFields(["geoLookupIp"]);
  const ip = requireIp(t("ipAddress"), geoLookupForm.ip);
  geoLookupResult.value = await api<GeoLookupResponse>(`geo/lookup?ip=${encodeURIComponent(ip)}`);
}

async function createTempBan() {
  validateFields(["tempBanIp", "tempBanPort"]);
  const payload = validateTempBanForm();
  await api("temp-bans", {
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

async function createDynamicRateLimit() {
  validateFields(["dynamicRatePort"]);
  const payload = validateDynamicRateLimitForm();
  await api("dynamic-rate-limits", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await refreshAll();
  showNotice(t("saved"));
}

async function createTrustedCidr() {
  validateFields(["trustedCidr"]);
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
  localStorage.removeItem("xdp-firewall-api-token");
  syncTabFromHash();
  window.addEventListener("hashchange", syncTabFromHash);
  void refreshCurrentView();
});

onBeforeUnmount(() => {
  stopDropStream();
  window.removeEventListener("hashchange", syncTabFromHash);
});

watch(apiToken, saveApiToken);
watch(tab, (value) => {
  if (value !== "drops") {
    stopDropStream();
  }
  void ensureTabLoaded(value).catch((err) => {
    error.value = err instanceof Error ? err.message : String(err);
  });
});
watch(dropNodeFilter, () => {
  clearDropEvents();
  if (dropStreaming.value) {
    stopDropStream();
    void startDropStream();
  }
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
  return {
    ...(ruleForm.rule_key.trim() ? { rule_key: ruleForm.rule_key.trim() } : {}),
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

function validateTempBanForm() {
  const protocol = requireOneOf(t("protocol"), tempBanForm.protocol, protocols);
  const port = optionalPort(tempBanForm.port);
  if (protocol === "icmp" && port !== null) {
    throwValidation(v("icmpPort"));
  }
  return {
    ip: requireIp(t("sourceIp"), tempBanForm.ip),
    protocol,
    port,
    duration_seconds: requirePositiveInteger(t("durationSeconds"), tempBanForm.duration_seconds),
    comment: String(tempBanForm.comment ?? "").trim() || null
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

function validateDynamicRateLimitForm() {
  const protocol = requireOneOf(t("protocol"), dynamicRateForm.protocol, protocols);
  const port = optionalPort(dynamicRateForm.port);
  if (protocol === "icmp" && port !== null) {
    throwValidation(v("icmpPort"));
  }
  return {
    enabled: true,
    priority: requireInteger(t("priority"), dynamicRateForm.priority),
    protocol,
    port,
    packets_per_second: requirePositiveInteger("PPS", dynamicRateForm.packets_per_second),
    burst: requirePositiveInteger(t("burst"), dynamicRateForm.burst),
    comment: String(dynamicRateForm.comment ?? "").trim() || null
  };
}

function validateTrustedCidrForm() {
  return {
    cidr: requireCidr("CIDR", trustedForm.cidr),
    comment: String(trustedForm.comment ?? "").trim() || null
  };
}

function validateFields(keys: FieldKey[]) {
  const results = keys.map((key) => validateField(key));
  if (results.every(Boolean)) {
    return;
  }
  const message = keys.map((key) => fieldErrors[key]).find(Boolean) || t("error");
  throwValidation(message);
}

function hasFieldErrors(keys: FieldKey[]) {
  return keys.some((key) => Boolean(fieldErrors[key]));
}

function validateTouchedField(key: FieldKey) {
  if (touchedFields[key] || fieldErrors[key]) {
    queueMicrotask(() => validateField(key));
  }
}

function validateFieldAfterUpdate(key: FieldKey) {
  queueMicrotask(() => validateField(key));
}

function validateField(key: FieldKey): boolean {
  touchedFields[key] = true;
  try {
    switch (key) {
      case "ruleCidr":
        requireCidr(t("ruleCidr"), ruleForm.cidr);
        break;
      case "rulePort":
        validateRulePortField();
        break;
      case "geoLookupIp":
        requireIp(t("ipAddress"), geoLookupForm.ip);
        break;
      case "tempBanIp":
        requireIp(t("sourceIp"), tempBanForm.ip);
        break;
      case "tempBanPort":
        validateProtocolPortField(tempBanForm.protocol, tempBanForm.port, true);
        break;
      case "dynamicRatePort":
        validateProtocolPortField(dynamicRateForm.protocol, dynamicRateForm.port, true);
        break;
      case "trustedCidr":
        requireCidr("CIDR", trustedForm.cidr);
        break;
    }
    delete fieldErrors[key];
    return true;
  } catch (err) {
    fieldErrors[key] = err instanceof Error ? err.message : String(err);
    return false;
  }
}

function validateRulePortField() {
  const protocol = requireOneOf(t("ruleProtocol"), ruleForm.protocol, protocols);
  validateProtocolPortField(protocol, ruleForm.port, true);
}

function validateProtocolPortField(protocolValue: unknown, portValue: unknown, allowAnyPort: boolean) {
  const protocol = requireOneOf(t("protocol"), protocolValue, protocols);
  const port = optionalPort(portValue);
  if (protocol === "icmp" && port !== null) {
    throwValidation(v("icmpPort"));
  }
  if (!allowAnyPort && protocol === "any" && port !== null) {
    throwValidation(v("anyPort"));
  }
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

function requirePositiveInteger(label: string, value: unknown): number {
  const number = requireInteger(label, value);
  if (number <= 0) {
    throwValidation(v("positive", label));
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

function requireIp(label: string, value: unknown): string {
  const ip = requireText(label, value);
  if (ip.includes("/")) {
    throwValidation(v("ipNoCidr", label));
  }
  if (isIpv4(ip) || isIpv6(ip)) {
    return ip;
  }
  throwValidation(v("invalid", label));
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
  const parts = cidr.split("/").map((part) => part.trim());
  if (parts.length !== 2) {
    throwValidation(v("cidrPrefixRequired", label));
  }
  if (!parts[1]) {
    throwValidation(v("cidrPrefixInteger", label));
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
  throw new Error(message);
}
</script>

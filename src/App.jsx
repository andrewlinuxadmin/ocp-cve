import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Page,
  Masthead,
  MastheadMain,
  MastheadBrand,
  MastheadContent,
  PageSection,
  Select,
  SelectOption,
  SelectList,
  MenuToggle,
  TextInputGroup,
  TextInputGroupMain,
  TextInputGroupUtilities,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  SearchInput,
  Spinner,
  EmptyState,
  EmptyStateBody,
  Label,
  Pagination,
  Alert,
  Split,
  SplitItem,
  Content,
  Bullseye,
  Button,
  Flex,
  FlexItem,
  Badge,
  Divider
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import TimesIcon from '@patternfly/react-icons/dist/esm/icons/times-icon';
import SunIcon from '@patternfly/react-icons/dist/esm/icons/sun-icon';
import MoonIcon from '@patternfly/react-icons/dist/esm/icons/moon-icon';
import redHatLogo from './assets/redhat-logo.png';

// --- constants ---

const GRAPH_API = 'https://api.openshift.com/api/upgrades_info/v1/graph';
const SECURITY_API = 'https://access.redhat.com/hydra/rest/securitydata';
const CHANNELS_API = 'https://api.github.com/repos/openshift/cincinnati-graph-data/contents/channels';

const CHANNEL_TYPES = ['candidate', 'fast', 'stable', 'eus'];
const NO_RESULTS = '__no_results__';

const SEVERITY_COLORS = {
  critical: 'red',
  important: 'orange',
  moderate: 'gold',
  low: 'blue'
};

const SEVERITY_ORDER = Object.keys(SEVERITY_COLORS);

const COLUMNS = [
  { key: 'cve', label: 'CVE' },
  { key: 'description', label: 'Description' },
  { key: 'severity', label: 'Severity' },
  { key: 'publicDate', label: 'CVE Date' },
  { key: 'rhsa', label: 'RHSA' },
  { key: 'rhsaDate', label: 'RHSA Date' },
  { key: 'fixedInVersion', label: 'Fixed In' }
];

// --- helpers ---

function compareSemver(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

function formatDate(iso) {
  if (!iso) return '';
  return iso.slice(0, 10);
}

function createItemId(prefix, value) {
  return `select-${prefix}-${String(value).replace(/\s+/g, '-')}`;
}

function capitalize(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : str;
}

// Severities present in a list of CVE rows, in a fixed order
function computeSeverityOptions(rows) {
  const present = new Set(rows.map(row => (row.severity || 'unknown').toLowerCase()));
  const ordered = SEVERITY_ORDER.filter(s => present.has(s));
  const extra = [...present].filter(s => !SEVERITY_ORDER.includes(s)).sort();
  return [...ordered, ...extra];
}

async function fetchGraph(channel) {
  const res = await fetch(`${GRAPH_API}?channel=${encodeURIComponent(channel)}`, {
    headers: { Accept: 'application/json' }
  });
  if (!res.ok) throw new Error(`Graph API: ${res.status}`);
  return res.json();
}

async function discoverChannels() {
  const res = await fetch(CHANNELS_API, { headers: { Accept: 'application/vnd.github+json' } });
  if (!res.ok) throw new Error(`Channels API: ${res.status}`);
  const data = await res.json();
  return data
    .filter(entry => entry.type === 'file' && entry.name.endsWith('.yaml'))
    .map(entry => entry.name.replace(/\.yaml$/, ''))
    .filter(name => CHANNEL_TYPES.some(t => name.startsWith(`${t}-`)));
}

async function fetchVersions(channel) {
  const graph = await fetchGraph(channel);
  // Channel names end in the target minor, e.g. "stable-4.20" -> "4.20". The graph
  // also includes older minors as upgrade-path predecessors; only offer the
  // channel's own minor in the Version combo.
  const minorMatch = channel.match(/(\d+\.\d+)$/);
  const minor = minorMatch ? minorMatch[1] : null;
  const versions = graph.nodes
    .map(n => n.version)
    .filter(v => !minor || v.startsWith(`${minor}.`))
    .sort((a, b) => compareSemver(b, a));
  return { versions, nodes: graph.nodes };
}

async function fetchCves(nodes, selectedVersion) {
  const newerNodes = nodes.filter(n => compareSemver(n.version, selectedVersion) > 0);
  const versionByRhsa = {};
  const rhsaIds = [];

  for (const node of newerNodes) {
    const url = node.metadata?.url || '';
    const match = url.match(/(RHSA-\d{4}:\d+)/);
    if (match && !versionByRhsa[match[1]]) {
      versionByRhsa[match[1]] = node.version;
      rhsaIds.push(match[1]);
    }
  }

  if (rhsaIds.length === 0) return [];

  // Fetch CSAF listing in batches
  const BATCH = 50;
  const csafMap = {};

  for (let i = 0; i < rhsaIds.length; i += BATCH) {
    const batch = rhsaIds.slice(i, i + BATCH);
    try {
      const res = await fetch(`${SECURITY_API}/csaf.json?rhsa_ids=${batch.join(',')}&per_page=1000`);
      if (!res.ok) continue;
      const data = await res.json();
      for (const item of data) {
        csafMap[item.RHSA] = { severity: item.severity, releasedOn: item.released_on, cves: item.CVEs || [] };
      }
    } catch { /* skip failed batches */ }
  }

  const activeRhsas = Object.keys(csafMap);
  if (activeRhsas.length === 0) return [];

  // Fetch CVE details in batches, with pagination
  const cveMap = {};
  for (let i = 0; i < activeRhsas.length; i += BATCH) {
    const batch = activeRhsas.slice(i, i + BATCH);
    let page = 1;
    while (true) {
      try {
        const res = await fetch(`${SECURITY_API}/cve.json?advisory=${batch.join(',')}&per_page=1000&page=${page}`);
        if (!res.ok) break;
        const data = await res.json();
        if (!data || data.length === 0) break;
        for (const cve of data) {
          if (!cveMap[cve.CVE]) {
            cveMap[cve.CVE] = {
              cve: cve.CVE,
              description: cve.bugzilla_description || '',
              severity: cve.severity || 'unknown',
              publicDate: cve.public_date || ''
            };
          }
        }
        if (data.length < 1000) break;
        page++;
      } catch { break; }
    }
  }

  // Combine RHSA + CVE data
  const results = [];
  const seen = new Set();
  for (const rhsa of activeRhsas) {
    const csaf = csafMap[rhsa];
    const fixedIn = versionByRhsa[rhsa] || '';
    for (const cveId of csaf.cves) {
      const key = `${cveId}|${rhsa}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const info = cveMap[cveId];
      results.push({
        cve: cveId,
        description: info?.description || '',
        severity: info?.severity || csaf.severity || 'unknown',
        publicDate: info?.publicDate || '',
        rhsa,
        rhsaDate: csaf.releasedOn || '',
        fixedInVersion: fixedIn
      });
    }
  }

  results.sort((a, b) => (b.rhsaDate || '').localeCompare(a.rhsaDate || ''));
  return results;
}

// --- component ---

export default function App() {
  // Theme (dark by default)
  const [isDarkTheme, setIsDarkTheme] = useState(true);

  useEffect(() => {
    document.documentElement.classList.toggle('pf-v6-theme-dark', isDarkTheme);
  }, [isDarkTheme]);

  // Data
  const [allChannels, setAllChannels] = useState([]);
  const [channelType, setChannelType] = useState('');
  const [selectedChannel, setSelectedChannel] = useState('');
  const [versions, setVersions] = useState([]);
  const [graphNodes, setGraphNodes] = useState([]);
  const [selectedVersion, setSelectedVersion] = useState('');
  const [cves, setCves] = useState([]);

  const [loadingChannels, setLoadingChannels] = useState(true);
  const [loadingVersions, setLoadingVersions] = useState(false);
  const [loadingCves, setLoadingCves] = useState(false);
  const [error, setError] = useState('');

  const [filterText, setFilterText] = useState('');
  const [severityFilter, setSeverityFilter] = useState([]);
  const [severityOpen, setSeverityOpen] = useState(false);
  const [sortIndex, setSortIndex] = useState(null);
  const [sortDirection, setSortDirection] = useState('asc');
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);

  // --- Channel type typeahead state ---
  const [typeOpen, setTypeOpen] = useState(false);
  const [typeInputValue, setTypeInputValue] = useState('');
  const [typeFilterValue, setTypeFilterValue] = useState('');
  const [typeFocusedIndex, setTypeFocusedIndex] = useState(null);
  const typeInputRef = useRef(null);

  // --- Channel typeahead state ---
  const [channelOpen, setChannelOpen] = useState(false);
  const [channelInputValue, setChannelInputValue] = useState('');
  const [channelFilterValue, setChannelFilterValue] = useState('');
  const [channelFocusedIndex, setChannelFocusedIndex] = useState(null);
  const channelInputRef = useRef(null);

  // --- Version typeahead state ---
  const [versionOpen, setVersionOpen] = useState(false);
  const [versionInputValue, setVersionInputValue] = useState('');
  const [versionFilterValue, setVersionFilterValue] = useState('');
  const [versionFocusedIndex, setVersionFocusedIndex] = useState(null);
  const versionInputRef = useRef(null);

  // Request counters used to discard stale async responses (e.g. a fast
  // channel/version change firing a new request before the previous one resolves)
  const versionsRequestId = useRef(0);
  const cvesRequestId = useRef(0);

  // Load channels on mount
  useEffect(() => {
    discoverChannels()
      .then(setAllChannels)
      .catch(e => setError(`Failed to load channels: ${e.message}`))
      .finally(() => setLoadingChannels(false));
  }, []);

  // Channels matching the selected type, sorted ascending by version
  const channelsForType = useMemo(() => {
    if (!channelType) return [];
    return allChannels
      .filter(c => c.startsWith(`${channelType}-`))
      .sort((a, b) => compareSemver(a.slice(channelType.length + 1), b.slice(channelType.length + 1)));
  }, [allChannels, channelType]);

  // Reset channel/version/CVEs when the channel type changes
  useEffect(() => {
    setSelectedChannel('');
    setChannelInputValue('');
    setVersions([]);
    setGraphNodes([]);
    setSelectedVersion('');
    setVersionInputValue('');
    setCves([]);
  }, [channelType]);

  // Load versions when the channel changes
  useEffect(() => {
    if (!selectedChannel) return;
    setSelectedVersion('');
    setVersionInputValue('');
    setCves([]);
    setLoadingVersions(true);
    setError('');
    const requestId = ++versionsRequestId.current;
    fetchVersions(selectedChannel)
      .then(({ versions: v, nodes }) => {
        if (requestId !== versionsRequestId.current) return; // a newer channel selection superseded this request
        setVersions(v);
        setGraphNodes(nodes);
      })
      .catch(e => {
        if (requestId !== versionsRequestId.current) return;
        setError(`Failed to load versions: ${e.message}`);
      })
      .finally(() => {
        if (requestId === versionsRequestId.current) setLoadingVersions(false);
      });
  }, [selectedChannel]);

  // Load CVEs when the version changes
  const loadCves = useCallback(() => {
    if (!selectedVersion || graphNodes.length === 0) return;
    setLoadingCves(true);
    setError('');
    setCves([]);
    setSeverityFilter([]);
    const requestId = ++cvesRequestId.current;
    fetchCves(graphNodes, selectedVersion)
      .then(data => {
        if (requestId !== cvesRequestId.current) return; // a newer version selection superseded this request
        setCves(data);
        setPage(1);
        // All severities start checked, since all rows are shown by default
        setSeverityFilter(computeSeverityOptions(data));
      })
      .catch(e => {
        if (requestId !== cvesRequestId.current) return;
        setError(`Failed to fetch CVEs: ${e.message}`);
      })
      .finally(() => {
        if (requestId === cvesRequestId.current) setLoadingCves(false);
      });
  }, [selectedVersion, graphNodes]);

  useEffect(() => { loadCves(); }, [loadCves]);

  // Severity options present in the current CVE list, in a fixed order
  const severityOptions = useMemo(() => computeSeverityOptions(cves), [cves]);

  // Filtering (severityFilter starts with every option checked, so all rows show by default)
  const filtered = useMemo(() => {
    let rows = cves.filter(row => severityFilter.includes((row.severity || 'unknown').toLowerCase()));
    if (filterText) {
      const lower = filterText.toLowerCase();
      rows = rows.filter(row => COLUMNS.some(col => String(row[col.key] || '').toLowerCase().includes(lower)));
    }
    return rows;
  }, [cves, filterText, severityFilter]);

  // Sorting
  const sorted = useMemo(() => {
    if (sortIndex === null) return filtered;
    const key = COLUMNS[sortIndex].key;
    return [...filtered].sort((a, b) => {
      const va = (a[key] || '').toLowerCase();
      const vb = (b[key] || '').toLowerCase();
      const cmp = va.localeCompare(vb);
      return sortDirection === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortIndex, sortDirection]);

  // Pagination
  const paginated = useMemo(() => {
    const start = (page - 1) * perPage;
    return sorted.slice(start, start + perPage);
  }, [sorted, page, perPage]);

  const handleSort = (_event, index, direction) => {
    setSortIndex(index);
    setSortDirection(direction);
  };

  const isLoading = loadingChannels || loadingVersions || loadingCves;

  // ===== Channel type typeahead =====

  const typeOptions = useMemo(() => {
    const list = typeFilterValue
      ? CHANNEL_TYPES.filter(t => t.toLowerCase().includes(typeFilterValue.toLowerCase()))
      : CHANNEL_TYPES;
    return list.length ? list : [NO_RESULTS];
  }, [typeFilterValue]);

  const closeTypeMenu = () => { setTypeOpen(false); setTypeFocusedIndex(null); };

  const selectType = (value) => {
    setChannelType(value);
    setTypeInputValue(capitalize(value));
    setTypeFilterValue('');
    closeTypeMenu();
  };

  const onTypeSelect = (_event, value) => {
    if (value && value !== NO_RESULTS) selectType(value);
  };

  const onTypeInputChange = (_event, value) => {
    setTypeInputValue(value);
    setTypeFilterValue(value);
    setTypeFocusedIndex(null);
    if (value.toLowerCase() !== channelType) setChannelType('');
    if (!typeOpen) setTypeOpen(true);
  };

  const onTypeInputKeyDown = (event) => {
    const focused = typeFocusedIndex !== null ? typeOptions[typeFocusedIndex] : null;
    if (event.key === 'Enter') {
      if (typeOpen && focused && focused !== NO_RESULTS) selectType(focused);
      else if (!typeOpen) setTypeOpen(true);
    } else if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
      event.preventDefault();
      if (!typeOpen) { setTypeOpen(true); return; }
      const count = typeOptions.length;
      let next = typeFocusedIndex === null
        ? (event.key === 'ArrowDown' ? 0 : count - 1)
        : (event.key === 'ArrowDown' ? (typeFocusedIndex + 1) % count : (typeFocusedIndex - 1 + count) % count);
      setTypeFocusedIndex(next);
    } else if (event.key === 'Escape') {
      closeTypeMenu();
    }
  };

  const onTypeClear = () => {
    setChannelType('');
    setTypeInputValue('');
    setTypeFilterValue('');
    closeTypeMenu();
    typeInputRef.current?.focus();
  };

  // ===== Channel typeahead =====

  const channelOptions = useMemo(() => {
    const list = channelFilterValue
      ? channelsForType.filter(c => c.toLowerCase().includes(channelFilterValue.toLowerCase()))
      : channelsForType;
    return list.length ? list : [NO_RESULTS];
  }, [channelsForType, channelFilterValue]);

  const closeChannelMenu = () => { setChannelOpen(false); setChannelFocusedIndex(null); };

  const selectChannel = (value) => {
    setSelectedChannel(value);
    setChannelInputValue(value);
    setChannelFilterValue('');
    closeChannelMenu();
  };

  const onChannelSelect = (_event, value) => {
    if (value && value !== NO_RESULTS) selectChannel(value);
  };

  const onChannelInputChange = (_event, value) => {
    setChannelInputValue(value);
    setChannelFilterValue(value);
    setChannelFocusedIndex(null);
    if (value !== selectedChannel) setSelectedChannel('');
    if (!channelOpen) setChannelOpen(true);
  };

  const onChannelInputKeyDown = (event) => {
    const focused = channelFocusedIndex !== null ? channelOptions[channelFocusedIndex] : null;
    if (event.key === 'Enter') {
      if (channelOpen && focused && focused !== NO_RESULTS) selectChannel(focused);
      else if (!channelOpen) setChannelOpen(true);
    } else if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
      event.preventDefault();
      if (!channelOpen) { setChannelOpen(true); return; }
      const count = channelOptions.length;
      let next = channelFocusedIndex === null
        ? (event.key === 'ArrowDown' ? 0 : count - 1)
        : (event.key === 'ArrowDown' ? (channelFocusedIndex + 1) % count : (channelFocusedIndex - 1 + count) % count);
      setChannelFocusedIndex(next);
    } else if (event.key === 'Escape') {
      closeChannelMenu();
    }
  };

  const onChannelClear = () => {
    setSelectedChannel('');
    setChannelInputValue('');
    setChannelFilterValue('');
    closeChannelMenu();
    channelInputRef.current?.focus();
  };

  // ===== Version typeahead =====

  const versionOptions = useMemo(() => {
    const list = versionFilterValue
      ? versions.filter(v => v.toLowerCase().includes(versionFilterValue.toLowerCase()))
      : versions;
    return list.length ? list : [NO_RESULTS];
  }, [versions, versionFilterValue]);

  const closeVersionMenu = () => { setVersionOpen(false); setVersionFocusedIndex(null); };

  const selectVersion = (value) => {
    setSelectedVersion(value);
    setVersionInputValue(value);
    setVersionFilterValue('');
    closeVersionMenu();
  };

  const onVersionSelect = (_event, value) => {
    if (value && value !== NO_RESULTS) selectVersion(value);
  };

  const onVersionInputChange = (_event, value) => {
    setVersionInputValue(value);
    setVersionFilterValue(value);
    setVersionFocusedIndex(null);
    if (value !== selectedVersion) setSelectedVersion('');
    if (!versionOpen) setVersionOpen(true);
  };

  const onVersionInputKeyDown = (event) => {
    const focused = versionFocusedIndex !== null ? versionOptions[versionFocusedIndex] : null;
    if (event.key === 'Enter') {
      if (versionOpen && focused && focused !== NO_RESULTS) selectVersion(focused);
      else if (!versionOpen) setVersionOpen(true);
    } else if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
      event.preventDefault();
      if (!versionOpen) { setVersionOpen(true); return; }
      const count = versionOptions.length;
      let next = versionFocusedIndex === null
        ? (event.key === 'ArrowDown' ? 0 : count - 1)
        : (event.key === 'ArrowDown' ? (versionFocusedIndex + 1) % count : (versionFocusedIndex - 1 + count) % count);
      setVersionFocusedIndex(next);
    } else if (event.key === 'Escape') {
      closeVersionMenu();
    }
  };

  const onVersionClear = () => {
    setSelectedVersion('');
    setVersionInputValue('');
    setVersionFilterValue('');
    closeVersionMenu();
    versionInputRef.current?.focus();
  };

  // ===== Severity multi-select (checkboxes) =====

  const onSeveritySelect = (_event, value) => {
    setSeverityFilter(prev =>
      prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]
    );
    setPage(1);
  };

  // Resets to the default state: every severity checked (all rows shown)
  const onSeverityClear = () => {
    setSeverityFilter(severityOptions);
    setPage(1);
  };

  return (
    <Page
      masthead={
        <Masthead>
          <MastheadMain>
            <MastheadBrand>
              <Flex alignItems={{ default: 'alignItemsCenter' }} spaceItems={{ default: 'spaceItemsSm' }}>
                <FlexItem>
                  <img src={redHatLogo} alt="Red Hat" style={{ height: '32px', width: 'auto' }} />
                </FlexItem>
                <FlexItem>
                  <Content component="h1" style={{ margin: 0 }}>
                    Red Hat OpenShift - CVE Viewer
                  </Content>
                </FlexItem>
              </Flex>
            </MastheadBrand>
          </MastheadMain>
          <MastheadContent>
            <Flex justifyContent={{ default: 'justifyContentFlexEnd' }} style={{ flexGrow: 1 }}>
              <FlexItem>
                <Button
                  variant="plain"
                  aria-label={isDarkTheme ? 'Switch to light theme' : 'Switch to dark theme'}
                  icon={isDarkTheme ? <SunIcon /> : <MoonIcon />}
                  onClick={() => setIsDarkTheme(prev => !prev)}
                />
              </FlexItem>
            </Flex>
          </MastheadContent>
        </Masthead>
      }
    >
      <PageSection>
        <Split hasGutter>
          <SplitItem>
            <Content component="p" style={{ marginBottom: 'var(--pf-t--global--spacer--xs)', fontWeight: 'bold' }}>Channel type</Content>
            <Select
              id="channel-type-select"
              isOpen={typeOpen}
              selected={channelType}
              onSelect={onTypeSelect}
              onOpenChange={(open) => { if (!open) closeTypeMenu(); }}
              toggle={toggleRef => (
                <MenuToggle
                  ref={toggleRef}
                  variant="typeahead"
                  aria-label="Channel type typeahead menu toggle"
                  onClick={() => { setTypeOpen(prev => !prev); typeInputRef.current?.focus(); }}
                  isExpanded={typeOpen}
                  isFullWidth
                  style={{ minWidth: '100px' }}
                >
                  <TextInputGroup isPlain>
                    <TextInputGroupMain
                      value={typeInputValue}
                      onClick={() => { if (!typeOpen) setTypeOpen(true); }}
                      onChange={onTypeInputChange}
                      onKeyDown={onTypeInputKeyDown}
                      id="channel-type-input"
                      autoComplete="off"
                      innerRef={typeInputRef}
                      placeholder="Select channel type"
                      role="combobox"
                      isExpanded={typeOpen}
                      aria-controls="channel-type-listbox"
                    />
                    <TextInputGroupUtilities {...(!typeInputValue ? { style: { display: 'none' } } : {})}>
                      <Button variant="plain" onClick={onTypeClear} aria-label="Clear channel type" icon={<TimesIcon />} />
                    </TextInputGroupUtilities>
                  </TextInputGroup>
                </MenuToggle>
              )}
              variant="typeahead"
            >
              <SelectList id="channel-type-listbox">
                {typeOptions.map((option, index) =>
                  option === NO_RESULTS ? (
                    <SelectOption key={NO_RESULTS} isAriaDisabled value={NO_RESULTS}>
                      No results found
                    </SelectOption>
                  ) : (
                    <SelectOption
                      key={option}
                      value={option}
                      isFocused={typeFocusedIndex === index}
                      id={createItemId('channel-type', option)}
                    >
                      {capitalize(option)}
                    </SelectOption>
                  )
                )}
              </SelectList>
            </Select>
          </SplitItem>

          <SplitItem>
            <Content component="p" style={{ marginBottom: 'var(--pf-t--global--spacer--xs)', fontWeight: 'bold' }}>Channel</Content>
            <Select
              id="channel-select"
              isOpen={channelOpen}
              selected={selectedChannel}
              onSelect={onChannelSelect}
              onOpenChange={(open) => { if (!open) closeChannelMenu(); }}
              isScrollable
              maxMenuHeight="300px"
              toggle={toggleRef => (
                <MenuToggle
                  ref={toggleRef}
                  variant="typeahead"
                  aria-label="Channel typeahead menu toggle"
                  onClick={() => { if (!channelType || loadingChannels) return; setChannelOpen(prev => !prev); channelInputRef.current?.focus(); }}
                  isExpanded={channelOpen}
                  isFullWidth
                  isDisabled={!channelType || loadingChannels}
                  style={{ minWidth: '100px' }}
                >
                  <TextInputGroup isPlain>
                    <TextInputGroupMain
                      value={channelInputValue}
                      onClick={() => { if (!channelOpen && channelType) setChannelOpen(true); }}
                      onChange={onChannelInputChange}
                      onKeyDown={onChannelInputKeyDown}
                      id="channel-input"
                      autoComplete="off"
                      innerRef={channelInputRef}
                      placeholder={loadingChannels ? 'Loading...' : 'Select channel'}
                      role="combobox"
                      isExpanded={channelOpen}
                      aria-controls="channel-listbox"
                    />
                    <TextInputGroupUtilities {...(!channelInputValue ? { style: { display: 'none' } } : {})}>
                      <Button variant="plain" onClick={onChannelClear} aria-label="Clear channel" icon={<TimesIcon />} />
                    </TextInputGroupUtilities>
                  </TextInputGroup>
                </MenuToggle>
              )}
              variant="typeahead"
            >
              <SelectList id="channel-listbox" key={channelType}>
                {channelOptions.map((option, index) =>
                  option === NO_RESULTS ? (
                    <SelectOption key={NO_RESULTS} isAriaDisabled value={NO_RESULTS}>
                      No results found
                    </SelectOption>
                  ) : (
                    <SelectOption
                      key={option}
                      value={option}
                      isFocused={channelFocusedIndex === index}
                      id={createItemId('channel', option)}
                    >
                      {option}
                    </SelectOption>
                  )
                )}
              </SelectList>
            </Select>
          </SplitItem>

          <SplitItem>
            <Content component="p" style={{ marginBottom: 'var(--pf-t--global--spacer--xs)', fontWeight: 'bold' }}>Version</Content>
            <Select
              id="version-select"
              isOpen={versionOpen}
              selected={selectedVersion}
              onSelect={onVersionSelect}
              onOpenChange={(open) => { if (!open) closeVersionMenu(); }}
              isScrollable
              maxMenuHeight="300px"
              toggle={toggleRef => (
                <MenuToggle
                  ref={toggleRef}
                  variant="typeahead"
                  aria-label="Version typeahead menu toggle"
                  onClick={() => { if (!selectedChannel || loadingVersions) return; setVersionOpen(prev => !prev); versionInputRef.current?.focus(); }}
                  isExpanded={versionOpen}
                  isFullWidth
                  isDisabled={!selectedChannel || loadingVersions}
                  style={{ minWidth: '90px' }}
                >
                  <TextInputGroup isPlain>
                    <TextInputGroupMain
                      value={versionInputValue}
                      onClick={() => { if (!versionOpen && selectedChannel) setVersionOpen(true); }}
                      onChange={onVersionInputChange}
                      onKeyDown={onVersionInputKeyDown}
                      id="version-input"
                      autoComplete="off"
                      innerRef={versionInputRef}
                      placeholder={loadingVersions ? 'Loading...' : 'Select version'}
                      role="combobox"
                      isExpanded={versionOpen}
                      aria-controls="version-listbox"
                    />
                    <TextInputGroupUtilities {...(!versionInputValue && !loadingVersions ? { style: { display: 'none' } } : {})}>
                      {loadingVersions ? (
                        <Spinner size="md" aria-label="Loading versions" />
                      ) : (
                        <Button variant="plain" onClick={onVersionClear} aria-label="Clear version" icon={<TimesIcon />} />
                      )}
                    </TextInputGroupUtilities>
                  </TextInputGroup>
                </MenuToggle>
              )}
              variant="typeahead"
            >
              <SelectList id="version-listbox" key={selectedChannel}>
                {versionOptions.map((option, index) =>
                  option === NO_RESULTS ? (
                    <SelectOption key={NO_RESULTS} isAriaDisabled value={NO_RESULTS}>
                      No results found
                    </SelectOption>
                  ) : (
                    <SelectOption
                      key={option}
                      value={option}
                      isFocused={versionFocusedIndex === index}
                      id={createItemId('version', option)}
                    >
                      {option}
                    </SelectOption>
                  )
                )}
              </SelectList>
            </Select>
          </SplitItem>

          {loadingCves && (
            <SplitItem>
              <div style={{ paddingTop: '28px' }}>
                <Spinner size="lg" aria-label="Fetching CVEs..." />
              </div>
            </SplitItem>
          )}
        </Split>
      </PageSection>

      {error && (
        <PageSection>
          <Alert variant="danger" title={error} isInline />
        </PageSection>
      )}

      {!loadingCves && cves.length > 0 && (
        <PageSection isFilled>
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem>
                <SearchInput
                  placeholder="Filter results..."
                  value={filterText}
                  onChange={(_event, value) => { setFilterText(value); setPage(1); }}
                  onClear={() => { setFilterText(''); setPage(1); }}
                />
              </ToolbarItem>
              <ToolbarItem>
                <Select
                  id="severity-select"
                  role="menu"
                  isOpen={severityOpen}
                  selected={severityFilter}
                  onSelect={onSeveritySelect}
                  onOpenChange={(open) => setSeverityOpen(open)}
                  toggle={toggleRef => (
                    <MenuToggle
                      ref={toggleRef}
                      onClick={() => setSeverityOpen(prev => !prev)}
                      isExpanded={severityOpen}
                      badge={severityFilter.length < severityOptions.length ? <Badge isRead>{severityFilter.length}</Badge> : undefined}
                    >
                      Severity
                    </MenuToggle>
                  )}
                >
                  <SelectList>
                    {severityOptions.map(option => (
                      <SelectOption key={option} value={option} hasCheckbox isSelected={severityFilter.includes(option)}>
                        <Label color={SEVERITY_COLORS[option] || 'grey'} isCompact>
                          {option}
                        </Label>
                      </SelectOption>
                    ))}
                    {severityFilter.length < severityOptions.length && (
                      <>
                        <Divider />
                        <SelectOption onClick={onSeverityClear}>Clear severity filter</SelectOption>
                      </>
                    )}
                  </SelectList>
                </Select>
              </ToolbarItem>
              <ToolbarItem>
                <Content component="small">{sorted.length} CVEs found</Content>
              </ToolbarItem>
              <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
                <Pagination
                  itemCount={sorted.length}
                  perPage={perPage}
                  page={page}
                  onSetPage={(_e, p) => setPage(p)}
                  onPerPageSelect={(_e, pp) => { setPerPage(pp); setPage(1); }}
                  isCompact
                />
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>

          <Table aria-label="CVE table" isStickyHeader>
            <Thead>
              <Tr>
                {COLUMNS.map((col, idx) => (
                  <Th
                    key={col.key}
                    sort={{ sortBy: { index: sortIndex, direction: sortDirection }, onSort: handleSort, columnIndex: idx }}
                    modifier={col.key === 'description' ? 'truncate' : undefined}
                    width={col.key === 'description' ? 30 : undefined}
                  >
                    {col.label}
                  </Th>
                ))}
              </Tr>
            </Thead>
            <Tbody>
              {paginated.map((row, ri) => (
                <Tr key={`${row.cve}-${row.rhsa}-${ri}`}>
                  <Td dataLabel="CVE">
                    <a href={`https://access.redhat.com/security/cve/${row.cve}`} target="_blank" rel="noopener noreferrer">
                      {row.cve}
                    </a>
                  </Td>
                  <Td dataLabel="Description" modifier="truncate">{row.description}</Td>
                  <Td dataLabel="Severity">
                    <Label color={SEVERITY_COLORS[row.severity?.toLowerCase()] || 'grey'}>
                      {row.severity}
                    </Label>
                  </Td>
                  <Td dataLabel="CVE Date">{formatDate(row.publicDate)}</Td>
                  <Td dataLabel="RHSA">
                    <a href={`https://access.redhat.com/errata/${row.rhsa}`} target="_blank" rel="noopener noreferrer">
                      {row.rhsa}
                    </a>
                  </Td>
                  <Td dataLabel="RHSA Date">{formatDate(row.rhsaDate)}</Td>
                  <Td dataLabel="Fixed In">{row.fixedInVersion}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>

          <Toolbar>
            <ToolbarContent>
              <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
                <Pagination
                  itemCount={sorted.length}
                  perPage={perPage}
                  page={page}
                  onSetPage={(_e, p) => setPage(p)}
                  onPerPageSelect={(_e, pp) => { setPerPage(pp); setPage(1); }}
                  isCompact
                />
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>
        </PageSection>
      )}

      {!isLoading && cves.length === 0 && selectedVersion && (
        <PageSection>
          <EmptyState>
            <EmptyStateBody>
              No CVEs found for versions newer than {selectedVersion} in channel {selectedChannel}.
            </EmptyStateBody>
          </EmptyState>
        </PageSection>
      )}

      {!isLoading && !selectedVersion && !loadingChannels && (
        <PageSection>
          <Bullseye>
            <EmptyState>
              <EmptyStateBody>
                Select a channel type, channel, and OpenShift version to view CVEs fixed in newer releases.
              </EmptyStateBody>
            </EmptyState>
          </Bullseye>
        </PageSection>
      )}
    </Page>
  );
}

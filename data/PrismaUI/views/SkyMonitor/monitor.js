(() => {
  'use strict';

  window.SkyMonitorSortPlugins = (source, sortMode) => {
    const plugins = Array.isArray(source) ? [...source] : [];
    if (sortMode === 'name') {
      plugins.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
    } else if (sortMode === 'recent') {
      plugins.sort((a, b) => Number(b.fileLastWriteTime || 0) - Number(a.fileLastWriteTime || 0) ||
        String(a.name || '').localeCompare(String(b.name || '')));
    } else {
      plugins.sort((a, b) => Number(a.loadOrderPosition ?? Number.MAX_SAFE_INTEGER) -
        Number(b.loadOrderPosition ?? Number.MAX_SAFE_INTEGER));
    }
    return plugins;
  };
})();

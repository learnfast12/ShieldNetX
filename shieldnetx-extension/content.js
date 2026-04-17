if (window.location.href.includes('localhost:9000')) {
  window.stop();
  window.location.href = chrome.runtime.getURL('blocked.html?score=85&level=CRITICAL&url=' + encodeURIComponent(window.location.href));
}

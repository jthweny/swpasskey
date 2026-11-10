// Service worker: the toolbar button opens the panel, and the badge says whether
// the bridge is answering, so the state is visible without a console.
const BRIDGE = "http://localhost:3000";

async function health() {
  try {
    const res = await fetch(BRIDGE + "/health", { cache: "no-store" });
    const json = await res.json();
    return !!json.ok;
  } catch (e) {
    return false;
  }
}

async function refreshBadge() {
  const ok = await health();
  await chrome.action.setBadgeText({ text: ok ? "ok" : "!" });
  await chrome.action.setBadgeBackgroundColor({ color: ok ? "#2f5d50" : "#8c2f2f" });
  await chrome.action.setTitle({
    title: ok ? "swpasskey bridge: ready" : "swpasskey bridge: daemon not reachable",
  });
}

chrome.runtime.onInstalled.addListener(refreshBadge);
chrome.runtime.onStartup.addListener(refreshBadge);
setInterval(refreshBadge, 5000);

chrome.action.onClicked.addListener(async (tab) => {
  if (tab.id === undefined) return;
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["panel.js"] });
  } catch (err) {
    console.error("[swpasskey bridge] cannot inject the panel:", err);
  }
});

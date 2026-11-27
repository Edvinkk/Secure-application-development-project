const keyword = new URLSearchParams(window.location.search).get("q");
const summary = document.getElementById("search-summary");

if (keyword) {
    summary.textContent = `Results for: ${keyword}`;
    summary.hidden = false;
}
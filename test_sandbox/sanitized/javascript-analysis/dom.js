function render(el) {
  const name = new URLSearchParams(location.search).get("name");
  el.textContent = "Hello " + name;
}

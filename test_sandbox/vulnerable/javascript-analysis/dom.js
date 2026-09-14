function render(el) {
  const name = new URLSearchParams(location.search).get("name");
  el.innerHTML = "<h1>Hello " + name + "</h1>";
}

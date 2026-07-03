(function () {
  var button = document.getElementById("mobileMenuButton");
  var sidebar = document.getElementById("sidebar");
  var backdrop = document.getElementById("sidebarBackdrop");
  if (!button || !sidebar || !backdrop) return;
  function close() {
    sidebar.classList.remove("open");
    backdrop.classList.remove("open");
    button.setAttribute("aria-expanded", "false");
  }
  button.addEventListener("click", function () {
    var open = !sidebar.classList.contains("open");
    sidebar.classList.toggle("open", open);
    backdrop.classList.toggle("open", open);
    button.setAttribute("aria-expanded", open ? "true" : "false");
  });
  backdrop.addEventListener("click", close);
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") close();
  });
})();

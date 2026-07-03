(function () {
  var bar = document.querySelector("[data-filter-bar]");
  if (!bar) return;
  bar.addEventListener("click", function (event) {
    var button = event.target.closest("[data-filter]");
    if (!button) return;
    var filter = button.getAttribute("data-filter");
    bar.querySelectorAll(".filter-button").forEach(function (item) { item.classList.remove("active"); });
    button.classList.add("active");
    document.querySelectorAll(".finding-card").forEach(function (card) {
      var visible = filter === "all" || card.dataset.severity === filter || card.dataset.status === filter;
      card.classList.toggle("filter-hidden", !visible);
    });
  });
})();

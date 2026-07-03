(function () {
  document.querySelectorAll(".finding-toggle").forEach(function (button) {
    button.addEventListener("click", function () {
      var card = button.closest(".finding-card");
      var open = card.classList.toggle("open");
      button.setAttribute("aria-expanded", open ? "true" : "false");
    });
  });
  window.addEventListener("load", function () {
    document.querySelectorAll(".flash").forEach(function (flash) {
      setTimeout(function () { flash.style.opacity = "0"; }, 4500);
      setTimeout(function () { flash.remove(); }, 5200);
    });
  });
})();

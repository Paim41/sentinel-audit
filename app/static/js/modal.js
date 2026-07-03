(function () {
  var modal = document.getElementById("deleteModal");
  if (!modal) return;
  var form = document.getElementById("deleteForm");
  var message = document.getElementById("deleteMessage");
  var closeButton = modal.querySelector("[data-modal-close]");
  document.querySelectorAll("[data-delete-open]").forEach(function (button) {
    button.addEventListener("click", function () {
      var id = button.getAttribute("data-delete-id");
      var name = button.getAttribute("data-delete-name");
      form.action = "/scans/" + encodeURIComponent(id) + "/delete";
      message.textContent = "Delete scan \"" + name + "\" permanently?";
      modal.classList.add("open");
      modal.setAttribute("aria-hidden", "false");
      closeButton.focus();
    });
  });
  function close() {
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
  }
  closeButton.addEventListener("click", close);
  modal.addEventListener("click", function (event) {
    if (event.target === modal) close();
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") close();
  });
})();

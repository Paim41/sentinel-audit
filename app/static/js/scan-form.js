(function () {
  var form = document.getElementById("scanForm");
  if (!form) return;
  var submit = document.getElementById("scanSubmit");
  var overlay = document.getElementById("scanLoading");
  var hostText = document.getElementById("scanHost");
  form.addEventListener("submit", function () {
    if (submit) {
      submit.disabled = true;
      submit.value = "Scanning";
    }
    if (overlay) {
      var input = form.querySelector("[name='target_url']");
      hostText.textContent = input && input.value ? input.value : "Resolving target";
      overlay.classList.add("active");
      overlay.setAttribute("aria-hidden", "false");
      window.SentinelProgress && window.SentinelProgress.start();
    }
  });
})();

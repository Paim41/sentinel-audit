(function () {
  var stages = [
    "Validating target",
    "Resolving hostname",
    "Checking HTTPS",
    "Inspecting TLS certificate",
    "Analysing response headers",
    "Reviewing cookies",
    "Inspecting forms",
    "Checking mixed content",
    "Checking safe public paths",
    "Calculating score",
    "Saving report"
  ];
  window.SentinelProgress = {
    start: function () {
      var stage = document.getElementById("scanStage");
      var progress = document.getElementById("scanProgress");
      var index = 0;
      function tick() {
        if (stage) stage.textContent = stages[Math.min(index, stages.length - 1)];
        if (progress) progress.style.width = Math.min(95, ((index + 1) / stages.length) * 100) + "%";
        index += 1;
        if (index < stages.length) setTimeout(tick, 420);
      }
      tick();
    }
  };
})();

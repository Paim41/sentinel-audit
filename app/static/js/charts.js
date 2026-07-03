(function () {
  if (!window.Chart) return;
  var scoreCanvas = document.getElementById("scoreChart");
  if (scoreCanvas) {
    var labels = JSON.parse(scoreCanvas.dataset.labels || "[]");
    var values = JSON.parse(scoreCanvas.dataset.values || "[]");
    new Chart(scoreCanvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [{ data: values, borderColor: "#b7ff3c", backgroundColor: "rgba(183,255,60,.12)", tension: .35, fill: true, pointRadius: 4 }]
      },
      options: chartOptions(false)
    });
  }
  var riskCanvas = document.getElementById("riskChart");
  if (riskCanvas) {
    var riskValues = JSON.parse(riskCanvas.dataset.values || "{}");
    new Chart(riskCanvas, {
      type: "doughnut",
      data: {
        labels: Object.keys(riskValues),
        datasets: [{ data: Object.values(riskValues), backgroundColor: ["#ff6262", "#ff8a8a", "#ffc857", "#65baff", "#b7ff3c"], borderColor: "#1b1f22" }]
      },
      options: chartOptions(true)
    });
  }
  function chartOptions(showLegend) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700 },
      plugins: { legend: { display: showLegend, labels: { color: "#d9dcdf", font: { family: "Times New Roman" } } } },
      scales: showLegend ? {} : {
        x: { ticks: { color: "#bcc1c5", font: { family: "Times New Roman" } }, grid: { color: "rgba(217,220,223,.12)" } },
        y: { min: 0, max: 100, ticks: { color: "#bcc1c5", font: { family: "Times New Roman" } }, grid: { color: "rgba(217,220,223,.12)" } }
      }
    };
  }
})();

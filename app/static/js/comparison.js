(function () {
  if (!window.Chart) return;
  var canvas = document.getElementById("comparisonChart");
  if (!canvas) return;
  new Chart(canvas, {
    type: "bar",
    data: {
      labels: ["Previous Score", "Current Score"],
      datasets: [{ data: [Number(canvas.dataset.previous || 0), Number(canvas.dataset.current || 0)], backgroundColor: ["#65baff", "#b7ff3c"] }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#d9dcdf", font: { family: "Times New Roman" } }, grid: { color: "rgba(217,220,223,.12)" } },
        y: { min: 0, max: 100, ticks: { color: "#d9dcdf", font: { family: "Times New Roman" } }, grid: { color: "rgba(217,220,223,.12)" } }
      }
    }
  });
})();

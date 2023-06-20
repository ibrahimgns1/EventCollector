document.addEventListener("DOMContentLoaded", function() {
  var totalLogEntries = document.getElementById("totalLogEntries").textContent;
  var logCounts = JSON.parse(document.getElementById("logCounts").textContent);

  var pieCtx = document.getElementById("pieChart").getContext("2d");
  var pieChart = new Chart(pieCtx, {
    type: "pie",
    data: {
      labels: Object.keys(logCounts),
      datasets: [
        {
          data: Object.values(logCounts),
          backgroundColor: [
            "rgba(255, 99, 132, 0.6)",
            "rgba(54, 162, 235, 0.6)",
            "rgba(255, 206, 86, 0.6)",
            "rgba(75, 192, 192, 0.6)",
            "rgba(153, 102, 255, 0.6)",
            "rgba(255, 159, 64, 0.6)"
          ]
        }
      ]
    },
    options: {
      responsive: true
    }
  });

  var barCtx = document.getElementById("barChart").getContext("2d");
  var barChart = new Chart(barCtx, {
    type: "bar",
    data: {
      labels: Object.keys(logCounts),
      datasets: [
        {
          label: "# of Entries",
          data: Object.values(logCounts),
          backgroundColor: [
            "rgba(75, 192, 192, 0.6)",
            "rgba(153, 102, 255, 0.6)",
            "rgba(255, 159, 64, 0.6)"
          ]
        }
      ]
    },
    options: {
      responsive: true,
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
});

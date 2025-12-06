document.addEventListener("DOMContentLoaded", function () {
  // Data will be injected by the template
  // This prevents linter errors from seeing template syntax

  // Blood Type Distribution Chart
  if (window.bloodData && Object.keys(window.bloodData).length > 0) {
    const bloodCtx = document.getElementById("bloodTypeChart");
    if (bloodCtx) {
      try {
        new Chart(bloodCtx, {
          type: "doughnut",
          data: {
            labels: Object.keys(window.bloodData),
            datasets: [
              {
                data: Object.values(window.bloodData),
                backgroundColor: [
                  "#FF6384",
                  "#36A2EB",
                  "#FFCE56",
                  "#4BC0C0",
                  "#9966FF",
                  "#FF9F40",
                  "#FF6384",
                  "#C9CBCF",
                ],
                borderColor: "white",
                borderWidth: 2,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: "bottom" },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering blood type chart:", err);
      }
    }
  }

  // Vaccination Status Chart
  if (window.vaccData && Object.keys(window.vaccData).length > 0) {
    const vaccCtx = document.getElementById("vaccinationChart");
    if (vaccCtx) {
      try {
        new Chart(vaccCtx, {
          type: "pie",
          data: {
            labels: Object.keys(window.vaccData),
            datasets: [
              {
                data: Object.values(window.vaccData),
                backgroundColor: [
                  "#28a745",
                  "#ffc107",
                  "#dc3545",
                  "#17a2b8",
                  "#6c757d",
                ],
                borderColor: "white",
                borderWidth: 2,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: "bottom" },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering vaccination chart:", err);
      }
    }
  }

  // Allergies Chart
  if (window.allergyData && Object.keys(window.allergyData).length > 0) {
    const allergiesCtx = document.getElementById("allergiesChart");
    if (allergiesCtx) {
      try {
        new Chart(allergiesCtx, {
          type: "bar",
          data: {
            labels: Object.keys(window.allergyData),
            datasets: [
              {
                label: "Count",
                data: Object.values(window.allergyData),
                backgroundColor: "#36A2EB",
                borderColor: "#36A2EB",
                borderWidth: 1,
              },
            ],
          },
          options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
            },
            scales: {
              x: { beginAtZero: true },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering allergies chart:", err);
      }
    }
  }

  // Past Illnesses Chart
  if (window.illnessData && Object.keys(window.illnessData).length > 0) {
    const illnessesCtx = document.getElementById("illnessesChart");
    if (illnessesCtx) {
      try {
        new Chart(illnessesCtx, {
          type: "bar",
          data: {
            labels: Object.keys(window.illnessData),
            datasets: [
              {
                label: "Count",
                data: Object.values(window.illnessData),
                backgroundColor: "#FF6384",
                borderColor: "#FF6384",
                borderWidth: 1,
              },
            ],
          },
          options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
            },
            scales: {
              x: { beginAtZero: true },
            },
          },
        });
      } catch (err) {
        console.error("Error rendering illnesses chart:", err);
      }
    }
  }

  // Apply data-width values to trend bars
  document
    .querySelectorAll(".trend-bar-fill[data-width]")
    .forEach((element) => {
      const width = element.getAttribute("data-width");
      element.style.width = width + "%";
    });
});

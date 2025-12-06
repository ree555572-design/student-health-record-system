// Main JavaScript file for Health Record Management System
// All data is handled by the backend via Flask routes

document.addEventListener("DOMContentLoaded", () => {
  // Auto-hide flash messages after 5 seconds
  const flashMessages = document.querySelectorAll('.flash-message');
  flashMessages.forEach(message => {
    setTimeout(() => {
      message.style.opacity = '0';
      setTimeout(() => {
        message.remove();
      }, 300);
    }, 5000);
  });


  // Form validation helpers
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      // Basic HTML5 validation will handle required fields
      // Additional custom validation can be added here
      if (!form.checkValidity()) {
        e.preventDefault();
        e.stopPropagation();
      }
      form.classList.add('was-validated');
    });
  });

// Dashboard Functions
async function fetchDashboardData() {
  const data = await apiFetch("/dashboard");
  if (!data) return;

  document.getElementById("total-students").textContent = data.total_students;
  document.getElementById("total-records").textContent = data.total_records;

  const tbody = document.querySelector("#recent-records-table tbody");
  tbody.innerHTML = "";

  if (!data.recent_records || data.recent_records.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" style="text-align: center; color: var(--text-light);">No records yet</td></tr>';
  } else {
    data.recent_records.forEach((record) => {
      const row = tbody.insertRow();
      row.innerHTML = `
        <td>${record.student_id}</td>
        <td>${record.visit_date}</td>
        <td>${record.diagnosis}</td>
        <td>${record.treatment}</td>
        <td>${new Date(record.created_at).toLocaleDateString()}</td>
      `;
    });
  }
}


// Utility function to show loading state
function showLoading(element) {
  if (element) {
    element.disabled = true;
    element.innerHTML = '<i class="bx bx-loader-alt bx-spin"></i> Loading...';
  }
}

// Utility function to hide loading state
function hideLoading(element, originalText) {
  if (element) {
    element.disabled = false;
    element.innerHTML = originalText;
  }
} })


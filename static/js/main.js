// Main JS file
document.addEventListener("DOMContentLoaded", () => {
  // Example: Auto-dismiss messages after 5 seconds
  const messages = document.querySelectorAll(".messages .card");
  if (messages.length > 0) {
    setTimeout(() => {
      messages.forEach((msg) => {
        msg.style.opacity = "0";
        setTimeout(() => msg.remove(), 500);
      });
    }, 5000);
  }
});

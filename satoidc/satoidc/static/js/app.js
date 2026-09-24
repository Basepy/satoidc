function copyText(value, feedbackSelector) {
  navigator.clipboard
    .writeText(value)
    .then(() => {
      const feedback = document.querySelector(feedbackSelector);
      if (feedback) {
        feedback.textContent = "Copiado.";
        feedback.classList.add("success");
        window.setTimeout(() => {
          feedback.textContent = "";
          feedback.classList.remove("success");
        }, 1800);
      }
    })
    .catch(() => {
      const feedback = document.querySelector(feedbackSelector);
      if (feedback) {
        feedback.textContent = "Nao foi possivel copiar automaticamente.";
        feedback.classList.add("error");
      }
    });
}

document.addEventListener("click", (event) => {
  const copyButton = event.target.closest("[data-copy]");
  if (copyButton) {
    copyText(copyButton.dataset.copy || "", copyButton.dataset.feedback || "");
  }
});

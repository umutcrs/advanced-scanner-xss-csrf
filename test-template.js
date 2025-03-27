function safeTemplateUsage(userName) {
  // Template literal güvenli kullanımı
  const greeting = `Merhaba ${userName}, hoş geldiniz!`;
  document.getElementById('greeting').textContent = greeting;
}
function safeTemplateUsage(userName) {
  // Template literal güvenli kullanımı - textContent ile
  const greeting = `Merhaba ${userName}, hoş geldiniz!`;
  document.getElementById("greeting").textContent = greeting;
}

function anotherSafeUsage(value) {
  // Bu da güvenli bir kullanım
  const element = document.getElementById("result");
  element.textContent = `Hesaplama sonucu: ${value}`;
}

function unsafeTemplateUsage(userInput) {
  // Bu tehlikeli bir kullanım - innerHTML 
  const content = `<div>${userInput}</div>`;
  document.getElementById("content").innerHTML = content;
}

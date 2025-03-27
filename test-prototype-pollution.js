"use strict";
// Bu gerçek bir güvenlik açığı içeriyor 
Object.defineProperty(Object.prototype, "__test", {
  value: "HACKED"
});

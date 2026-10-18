// portal.js — pequeña interacción del portal interno (sin dependencias externas).
(function () {
  "use strict";

  function pad(n) { return n < 10 ? "0" + n : "" + n; }

  function tick() {
    var el = document.getElementById("reloj");
    if (!el) return;
    var d = new Date();
    el.textContent = "Hora del servidor local: " +
      d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
      pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  document.addEventListener("DOMContentLoaded", function () {
    tick();
    setInterval(tick, 1000);
  });
})();
